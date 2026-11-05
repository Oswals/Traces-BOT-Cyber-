"""
Rédacteur PAR DÉFAUT, sans IA : chaque texte est soit extrait d'une source
officielle (SOURCE), soit calculé à partir des données (CALCULÉ), soit tiré
d'un contenu rédigé à l'avance et vérifié (BIBLIOTHÈQUE). Rien n'est inventé.

Ordre de préférence pour les 5 points « Comprendre » (voir CLAUDE.md) :
  C'est quoi ?          glossaire CWE  > code CWE brut de la NVD
  Qui est touché ?      CERT-FR        > CISA > NVD
  Gravité               calcul à partir du vecteur CVSS (cvss.py)
  Attaquant             CERT-FR        > CISA (EN) > NVD (EN)
  Se protéger           CERT-FR        > CISA (EN)
"""

import json
import logging
from functools import cache
from pathlib import Path

from enrichissement.faille import Faille

from . import cvss
from .base import Bloc, Redacteur
from .outils import (article_reference, bulletin_certfr, couper, liste_fr, lien_nvd,
                     niveau, nom_produit, virgule)

log = logging.getLogger(__name__)

FICHIER_GLOSSAIRE = Path(__file__).parent / "glossaire_cwe.json"
LONGUEUR_RESUME = 230
LONGUEUR_SOLUTION = 400
CWE_MAX = 2          # types de faille affichés dans la fiche d'identité
SYSTEMES_MAX = 3      # au-delà, « et N autres »
LIBELLES_NIVEAU = {"faible": "faible", "moyenne": "moyenne", "haute": "haute",
                   "critique": "critique", "inconnu": "non évaluée"}


@cache  # le fichier n'est lu qu'une fois, au premier appel
def glossaire() -> dict:
    try:
        donnees = json.loads(FICHIER_GLOSSAIRE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as erreur:
        log.error("Glossaire CWE illisible (%s) : le point « C'est quoi ? » restera brut", erreur)
        return {}
    return {cle: valeur for cle, valeur in donnees.items() if cle.startswith("CWE-")}


class SansIA(Redacteur):
    nom = "sans IA"

    # --- Titres -------------------------------------------------------------------

    def titre_une(self, faille: Faille) -> str:
        niv = niveau(faille.score)
        if niv == "inconnu":
            qualificatif = "une faille déjà exploitée" if faille.exploitee else "une nouvelle faille"
        elif niv == "critique":
            qualificatif = "une faille critique" + (" déjà exploitée" if faille.exploitee else "")
        else:
            qualificatif = f"une faille de gravité {LIBELLES_NIVEAU[niv]}"
            if faille.exploitee:
                qualificatif += ", déjà exploitée"
        return f"{nom_produit(faille)} : {qualificatif}"

    def titre_faille(self, faille: Faille) -> str:
        # « Produit : type de faille » si le glossaire connaît la CWE, sinon le titre officiel
        entree = self._entree_glossaire(faille)
        if entree:
            nom = entree[1]["nom"]
            return f"{nom_produit(faille)} : {nom[0].lower() + nom[1:]}"
        return article_reference(faille).titre

    def type_de_faille(self, faille: Faille) -> str:
        if not (faille.nvd and faille.nvd.cwes):
            return "non précisé"
        noms = [f"{cwe} · {glossaire()[cwe]['nom']}" if cwe in glossaire() else cwe
                for cwe in faille.nvd.cwes]
        # Les CWE connues du glossaire d'abord (les plus parlantes)
        noms.sort(key=lambda nom: "·" not in nom)
        return liste_fr(noms, CWE_MAX)

    # --- Résumé de la une -----------------------------------------------------------

    def resume(self, faille: Faille) -> Bloc:
        bulletin, article = bulletin_certfr(faille)
        if bulletin and bulletin.resume:
            return Bloc(couper(bulletin.resume, LONGUEUR_RESUME), "source", "CERT-FR", article.lien)
        reference = article_reference(faille)
        if reference.texte_source:
            return Bloc(couper(reference.texte_source, LONGUEUR_RESUME), "source",
                        reference.source, reference.lien, reference.langue)
        if faille.nvd and faille.nvd.description:
            return Bloc(couper(faille.nvd.description, LONGUEUR_RESUME), "source", "NVD (EN)",
                        lien_nvd(faille.cve), "en")
        return Bloc("Non précisé par la source.", "source", reference.source, reference.lien)

    # --- Les 5 points « Comprendre » ----------------------------------------------------

    def comprendre(self, faille: Faille) -> list[Bloc]:
        points = [
            ("C'est quoi ?", self._quoi(faille)),
            ("Qui est touché ?", self._qui(faille)),
            ("Gravité", self._gravite(faille)),
            ("Que peut faire un attaquant ?", self._attaquant(faille)),
            ("Comment se protéger ?", self._proteger(faille)),
        ]
        for question, bloc in points:
            bloc.question = question
        return [bloc for _, bloc in points]

    def _quoi(self, faille: Faille) -> Bloc:
        entree = self._entree_glossaire(faille)
        if entree:
            cwe, fiche = entree
            return Bloc(f"{fiche['nom']}. {fiche['explication']}", "bibliotheque",
                        f"Glossaire {cwe}", fiche["lien"])
        if faille.nvd and faille.nvd.cwes:
            cwe = faille.nvd.cwes[0]
            numero = cwe.removeprefix("CWE-")
            return Bloc(f"Type de faille {', '.join(faille.nvd.cwes)} (pas encore dans le glossaire TRACES).",
                        "source", "NVD", f"https://cwe.mitre.org/data/definitions/{numero}.html")
        return Bloc("Type de faille non précisé par la NVD.", "source", "NVD", lien_nvd(faille.cve))

    def _qui(self, faille: Faille) -> Bloc:
        bulletin, article = bulletin_certfr(faille)
        if bulletin and bulletin.systemes:
            return Bloc(liste_fr(bulletin.systemes, SYSTEMES_MAX) + ".", "source", "CERT-FR", article.lien)
        if faille.kev and faille.kev.details.get("produit"):
            return Bloc(nom_produit(faille) + ".", "source", "CISA", faille.kev.lien)
        if faille.nvd and faille.nvd.produits:
            return Bloc(liste_fr(faille.nvd.produits, SYSTEMES_MAX) + ".", "source", "NVD", lien_nvd(faille.cve))
        return Bloc("Non précisé par la source.", "source", "NVD", lien_nvd(faille.cve))

    def _gravite(self, faille: Faille) -> Bloc:
        if faille.score is None:
            texte = "Pas encore évaluée par la NVD."
            if faille.exploitee:
                texte += " Des attaques réelles ont pourtant déjà été observées (catalogue CISA)."
            return Bloc(texte, "calcule", "NVD", lien_nvd(faille.cve))

        texte = f"{virgule(faille.score)} sur 10, gravité {LIBELLES_NIVEAU[niveau(faille.score)]}"
        phrase = cvss.phrase_gravite(faille.nvd.vecteur)
        texte += f" : {phrase}." if phrase else "."
        # L'exploitation n'est pas répétée ici : la pastille « Exploitée » est juste à côté
        return Bloc(texte, "calcule", f"CVSS {faille.nvd.version_cvss}", lien_nvd(faille.cve))

    def _attaquant(self, faille: Faille) -> Bloc:
        bulletin, article = bulletin_certfr(faille)
        if bulletin and bulletin.risques:
            return Bloc(". ".join(bulletin.risques) + ".", "source", "CERT-FR", article.lien)
        if faille.kev and faille.kev.texte_source:
            return Bloc(faille.kev.texte_source, "source", "CISA (EN)", faille.kev.lien, "en")
        if faille.nvd and faille.nvd.description:
            return Bloc(couper(faille.nvd.description, LONGUEUR_RESUME), "source", "NVD (EN)",
                        lien_nvd(faille.cve), "en")
        return Bloc("Non précisé par la source.", "source", "NVD", lien_nvd(faille.cve))

    def _proteger(self, faille: Faille) -> Bloc:
        bulletin, article = bulletin_certfr(faille)
        if bulletin and bulletin.solution:
            texte = bulletin.solution
            # Phrase type du CERT-FR : on nomme le bulletin de l'éditeur au lieu de « cf. section Documentation »
            if "cf. section Documentation" in texte and bulletin.documentation:
                texte = texte.replace("(cf. section Documentation)", "").rstrip(" .") + \
                        f" : « {bulletin.documentation[0]['titre']} »."
            if bulletin.contournement:
                texte += " En attendant : " + bulletin.contournement
            return Bloc(couper(texte, LONGUEUR_SOLUTION), "source", "CERT-FR", article.lien)
        if faille.kev and faille.kev.details.get("action_requise"):
            return Bloc(faille.kev.details["action_requise"], "source", "CISA (EN)", faille.kev.lien, "en")
        return Bloc("Non précisé par la source. Surveiller le site de l'éditeur pour un correctif.",
                    "calcule", "Aucune source", "")

    # --- Outils ------------------------------------------------------------------------

    def _entree_glossaire(self, faille: Faille) -> tuple[str, dict] | None:
        """Première CWE de la faille présente dans le glossaire, avec sa fiche."""
        if not faille.nvd:
            return None
        for cwe in faille.nvd.cwes:
            if cwe in glossaire():
                return cwe, glossaire()[cwe]
        return None
