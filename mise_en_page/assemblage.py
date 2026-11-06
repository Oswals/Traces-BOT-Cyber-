"""
Assemblage : transforme la sélection du jour en dictionnaire « numéro », avec
exactement la même structure que mise_en_page/exemple.py (le numéro de démo).
Les gabarits ne voient donc aucune différence entre vraies et fausses données.

Les textes sont demandés au rédacteur (redaction/) : l'assemblage ne rédige
rien lui-même, il range. Changer de rédacteur ne change pas ce fichier.
"""

import json
import logging
from collections import Counter
from datetime import date

import config
from collecteurs.article import Article
from enrichissement.faille import Faille
from redaction import Redacteur, SansIA, cvss
from redaction.outils import article_reference, bulletin_certfr, couper, niveau, nom_produit
from selection import Selection
from selection.arnaque import ChoixArnaque

log = logging.getLogger(__name__)

MOIS = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet",
        "août", "septembre", "octobre", "novembre", "décembre"]
LONGUEUR_BREVE = 160    # caractères gardés du résumé d'une brève
LONGUEUR_ALERTE = 260   # résumé de l'alerte de la rubrique Arnaques
# Le magazine est au format A4 : au-delà, la page déborde (cadre orange à l'écran)
LONGUEUR_POINT_UNE = 200     # page « À la une » : 5 points + profil + fiche d'identité (4 lignes max)
LONGUEUR_POINT_FAILLE = 90   # page « Failles » : 3 fiches de 5 points, 2 lignes max par point (texte complet : lien source)


def assembler(selection: Selection, articles: list[Article], failles: list[Faille],
              numero: int, jour: date, redacteur: Redacteur | None = None,
              histoire: dict | None = None) -> dict:
    redacteur = redacteur or SansIA()
    return {
        "demo": False,
        "numero": numero,
        "date": date_fr(jour),
        "bref": _bref(articles, failles),
        "une": _une(selection.une, redacteur),
        "failles": [_fiche_faille(f, redacteur) for f in selection.failles],
        "radar": _radar(selection, articles, failles),
        "arnaque": _arnaque(selection.arnaque),
        "histoire": histoire,  # préparée par histoire/mise_en_forme.py
        "lexique": [],      # lexique.json : étape 7
    }


# --- Numéro et date -------------------------------------------------------------

def numero_du_jour(jour: date) -> int:
    """Numéro suivant le dernier publié ; le même si on relance le même jour."""
    dernier = {"numero": 0, "date": ""}
    if config.FICHIER_NUMERO.exists():
        try:
            dernier = json.loads(config.FICHIER_NUMERO.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            log.warning("%s est corrompu, la numérotation repart à 1", config.FICHIER_NUMERO.name)

    numero = dernier["numero"] if dernier["date"] == jour.isoformat() else dernier["numero"] + 1
    config.FICHIER_NUMERO.write_text(json.dumps({"numero": numero, "date": jour.isoformat()}),
                                     encoding="utf-8")
    return numero


def date_fr(jour: date) -> str:
    """date(2026, 11, 1) -> "1er novembre 2026" (sans dépendre des réglages de Windows)."""
    numero_jour = "1er" if jour.day == 1 else str(jour.day)
    return f"{numero_jour} {MOIS[jour.month - 1]} {jour.year}"


# --- Page 2 : le numéro en bref ---------------------------------------------------

def _bref(articles: list[Article], failles: list[Faille]) -> dict:
    return {
        "failles": len(failles),
        "critiques": sum(niveau(f.score) == "critique" for f in failles),
        "exploitees": sum(f.exploitee for f in failles),
        "sources": len({a.source for a in articles}),
        "articles": len(articles),
    }


# --- Pages 1 et 3 : la une --------------------------------------------------------

def _une(faille: Faille, redacteur: Redacteur) -> dict:
    reference = article_reference(faille)
    vecteur = faille.nvd.vecteur if faille.nvd else ""
    return {
        "titre": redacteur.titre_une(faille),
        "titre_officiel": reference.titre,
        "cve": faille.cve,
        "produit": nom_produit(faille),
        "score": faille.score,
        "niveau": niveau(faille.score),
        "exploitee": faille.exploitee,
        "resume": redacteur.resume(faille).en_dict(),
        "fiche": _fiche_identite(faille, reference, redacteur),
        "profil": cvss.profil(vecteur),
        "vecteur": vecteur,
        "comprendre": [_raccourcir(b.en_dict(), LONGUEUR_POINT_UNE) for b in redacteur.comprendre(faille)],
        "lien": reference.lien,
    }


def _fiche_identite(faille: Faille, reference: Article, redacteur: Redacteur) -> list[tuple[str, str]]:
    fiche = [("CVE", faille.cve), ("Produit", nom_produit(faille)),
             ("Type de faille", redacteur.type_de_faille(faille))]
    if faille.kev and faille.kev.date:
        fiche.append(("Exploitée depuis", f"{faille.kev.date:%d/%m/%Y} (CISA KEV)"))
    if reference.date:
        fiche.append(("Publication", f"{reference.source} · {date_fr(reference.date)}"))
    fiche.append(("Sources", ", ".join(faille.sources)))
    return fiche


# --- Page 4 : failles exploitées -------------------------------------------------------

def _fiche_faille(faille: Faille, redacteur: Redacteur) -> dict:
    return {
        "cve": faille.cve,
        "produit": nom_produit(faille),
        "score": faille.score,
        "niveau": niveau(faille.score),
        "titre": redacteur.titre_faille(faille),
        "exploitee": faille.exploitee,
        # Pas de bulletin du CERT-FR : les textes officiels sont ceux de la CISA, en anglais
        "en_anglais": bulletin_certfr(faille)[0] is None,
        "lien": article_reference(faille).lien,
        "points": [_raccourcir(b.en_dict(), LONGUEUR_POINT_FAILLE) for b in redacteur.comprendre(faille)],
    }


def _raccourcir(point: dict, longueur: int) -> dict:
    point["texte"] = couper(point["texte"], longueur)
    return point


# --- Page 5 : radar ------------------------------------------------------------------

def _radar(selection: Selection, articles: list[Article], failles: list[Faille]) -> dict:
    niveaux = Counter(niveau(f.score) for f in failles)
    sources = Counter(a.source for a in articles)
    return {
        "gravite": [{"niveau": n, "nombre": niveaux[n]} for n in ("critique", "haute", "moyenne", "faible")],
        "sans_score": niveaux["inconnu"],
        "provenance": [{"source": s, "nombre": n} for s, n in sources.most_common()],
        "breves_monde": [_breve(a) for a in selection.breves_monde],
        "breves_france": [_breve(a) for a in selection.breves_france],
    }


# --- Page 6 : arnaques ------------------------------------------------------------------

def _arnaque(choix: ChoixArnaque) -> dict:
    alerte = None
    if choix.alerte:
        a = choix.alerte
        alerte = {"titre": a["titre"], "resume": couper(a["resume"], LONGUEUR_ALERTE), "source": a["source"],
                  "lien": a["lien"], "langue": a["langue"], "date": date_fr(a["date"]) if a["date"] else ""}
    return {
        "mode": choix.mode,
        "rubrique": "La fiche du numéro" if choix.mode == "fiche" else "L'arnaque du moment",
        "alerte": alerte,
        "fiche": choix.fiche,
        "lien_cybermalveillance": config.LIEN_CYBERMALVEILLANCE,
    }


def _breve(article: Article) -> dict:
    return {"titre": article.titre, "resume": couper(article.texte_source, LONGUEUR_BREVE),
            "source": article.source, "langue": article.langue, "lien": article.lien}
