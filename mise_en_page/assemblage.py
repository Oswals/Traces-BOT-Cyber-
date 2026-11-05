"""
Assemblage : transforme la sélection du jour en dictionnaire « numéro », avec
exactement la même structure que mise_en_page/exemple.py (le numéro de démo).
Les gabarits ne voient donc aucune différence entre vraies et fausses données.

Version de l'étape 5 : les textes viennent tels quels des sources (souvent en
anglais pour la CISA et la NVD). L'étape 6 les améliorera : extraction des
sections du CERT-FR, glossaire CWE, profil CVSS traduit en français.
"""

import json
import logging
from collections import Counter
from datetime import date

import config
from collecteurs.article import Article
from enrichissement.faille import Faille
from selection import Selection, est_avis

log = logging.getLogger(__name__)

MOIS = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet",
        "août", "septembre", "octobre", "novembre", "décembre"]
LIBELLES_NIVEAU = {"faible": "faible", "moyenne": "moyenne", "haute": "haute",
                   "critique": "critique", "inconnu": "non évaluée"}
LONGUEUR_RESUME = 600   # caractères gardés du résumé de la une
LONGUEUR_BREVE = 220    # caractères gardés du résumé d'une brève


def assembler(selection: Selection, articles: list[Article], failles: list[Faille],
              numero: int, jour: date) -> dict:
    return {
        "demo": False,
        "numero": numero,
        "date": date_fr(jour),
        "bref": _bref(articles, failles),
        "une": _une(selection.une),
        "failles": [_fiche_faille(f) for f in selection.failles],
        "radar": _radar(selection, articles, failles),
        "histoire": None,   # bibliothèque Histoire : étape 7
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

def _une(faille: Faille) -> dict:
    reference = article_reference(faille)
    produit = nom_produit(faille)
    niv = niveau(faille.score)

    # Résumé : celui de l'article de référence, sinon la description NVD (en anglais)
    if reference.texte_source:
        resume = {"texte": couper(reference.texte_source, LONGUEUR_RESUME), "langue": reference.langue,
                  "provenance": "source", "source": reference.source, "lien": reference.lien}
    else:
        resume = {"texte": faille.nvd.description if faille.nvd else "Non précisé par la source.",
                  "langue": "en", "provenance": "source", "source": "NVD", "lien": lien_nvd(faille.cve)}

    return {
        "titre": titre_construit(faille, produit),
        "titre_officiel": reference.titre,
        "cve": faille.cve,
        "produit": produit,
        "score": faille.score,
        "niveau": niv,
        "exploitee": faille.exploitee,
        "resume": resume,
        "fiche": _fiche_identite(faille, produit, reference),
        "profil": [],   # les 8 cases traduites du vecteur CVSS : étape 6 (cvss.py)
        "vecteur": faille.nvd.vecteur if faille.nvd else "",
        "comprendre": cinq_points(faille),
        "lien": reference.lien,
    }


def titre_construit(faille: Faille, produit: str) -> str:
    """Titre calculé à partir des données, ex. « Fortinet FortiOS : une faille critique déjà exploitée »."""
    niv = niveau(faille.score)
    if niv == "inconnu":
        qualificatif = "une faille déjà exploitée" if faille.exploitee else "une nouvelle faille"
    elif niv == "critique":
        qualificatif = "une faille critique" + (" déjà exploitée" if faille.exploitee else "")
    else:
        qualificatif = f"une faille de gravité {LIBELLES_NIVEAU[niv]}"
        if faille.exploitee:
            qualificatif += ", déjà exploitée"
    return f"{produit} : {qualificatif}"


def _fiche_identite(faille: Faille, produit: str, reference: Article) -> list[tuple[str, str]]:
    cwes = ", ".join(faille.nvd.cwes) if faille.nvd and faille.nvd.cwes else "non précisé"
    fiche = [("CVE", faille.cve), ("Produit", produit), ("Type de faille", cwes)]
    if faille.kev and faille.kev.date:
        fiche.append(("Exploitée depuis", f"{faille.kev.date:%d/%m/%Y} (CISA KEV)"))
    if reference.date:
        fiche.append(("Publication", f"{reference.source} · {date_fr(reference.date)}"))
    if faille.nvd and faille.nvd.vecteur:
        fiche.append(("Vecteur CVSS", faille.nvd.vecteur))
    fiche.append(("Sources", ", ".join(faille.sources)))
    return fiche


# --- Les 5 points « Comprendre » (version étape 5, données brutes) ----------------------

def cinq_points(faille: Faille) -> list[dict]:
    nvd, kev = faille.nvd, faille.kev
    certfr = next((a for a in faille.articles if a.source == "CERT-FR"), None)

    # 1. C'est quoi ? Le code CWE donné par la NVD (le glossaire en français arrive à l'étape 6)
    if nvd and nvd.cwes:
        quoi = point("C'est quoi ?", "source", "NVD", f"Type de faille : {', '.join(nvd.cwes)}.",
                     lien_nvd(faille.cve))
    else:
        quoi = point("C'est quoi ?", "source", "NVD", "Type de faille non précisé par la NVD.",
                     lien_nvd(faille.cve))

    # 2. Qui est touché ?
    if kev and kev.details.get("produit"):
        qui = point("Qui est touché ?", "source", "CISA", nom_produit(faille), kev.lien)
    elif nvd and nvd.produits:
        qui = point("Qui est touché ?", "source", "NVD", ", ".join(nvd.produits[:5]), lien_nvd(faille.cve))
    else:
        qui = point("Qui est touché ?", "source", "NVD", "Non précisé par la source.")

    # 3. Gravité (calculée à partir du score)
    if faille.score is not None:
        texte = f"{virgule(faille.score)} sur 10, gravité {LIBELLES_NIVEAU[niveau(faille.score)]}."
        if faille.exploitee:
            texte += " Des attaques réelles ont été observées (catalogue CISA)."
        gravite = point("Gravité", "calcule", f"CVSS {nvd.version_cvss} (NVD)", texte)
    else:
        gravite = point("Gravité", "calcule", "NVD", "Pas encore évaluée par la NVD.")

    # 4. Que peut faire un attaquant ? (description officielle, en anglais)
    if kev and kev.texte_source:
        attaquant = point("Que peut faire un attaquant ?", "source", "CISA (EN)", kev.texte_source, kev.lien)
    elif nvd and nvd.description:
        attaquant = point("Que peut faire un attaquant ?", "source", "NVD (EN)",
                          couper(nvd.description, LONGUEUR_RESUME), lien_nvd(faille.cve))
    else:
        attaquant = point("Que peut faire un attaquant ?", "source", "NVD", "Non précisé par la source.")

    # 5. Comment se protéger ?
    if kev and kev.details.get("action_requise"):
        proteger = point("Comment se protéger ?", "source", "CISA (EN)", kev.details["action_requise"], kev.lien)
    elif certfr:
        proteger = point("Comment se protéger ?", "source", "CERT-FR",
                         "Voir la section « Solution » de la publication du CERT-FR.", certfr.lien)
    else:
        proteger = point("Comment se protéger ?", "source", "NVD", "Non précisé par la source.")

    return [quoi, qui, gravite, attaquant, proteger]


def point(question: str, provenance: str, source: str, texte: str, lien: str = "") -> dict:
    return {"question": question, "provenance": provenance, "source": source, "texte": texte, "lien": lien}


# --- Page 4 : failles exploitées -------------------------------------------------------

def _fiche_faille(faille: Faille) -> dict:
    reference = article_reference(faille)
    return {
        "cve": faille.cve,
        "produit": nom_produit(faille),
        "score": faille.score,
        "niveau": niveau(faille.score),
        "titre": reference.titre,
        "exploitee": faille.exploitee,
        # Pas de publication du CERT-FR : les textes officiels sont ceux de la CISA, en anglais
        "en_anglais": not any(a.source == "CERT-FR" for a in faille.articles),
        "lien": reference.lien,
        "points": cinq_points(faille),
    }


# --- Page 5 : radar ------------------------------------------------------------------

def _radar(selection: Selection, articles: list[Article], failles: list[Faille]) -> dict:
    niveaux = Counter(niveau(f.score) for f in failles)
    sources = Counter(a.source for a in articles)
    alerte = selection.alerte_arnaque
    return {
        "gravite": [{"niveau": n, "nombre": niveaux[n]} for n in ("critique", "haute", "moyenne", "faible")],
        "sans_score": niveaux["inconnu"],
        "provenance": [{"source": s, "nombre": n} for s, n in sources.most_common()],
        "breves_monde": [_breve(a) for a in selection.breves_monde],
        "breves_france": [_breve(a) for a in selection.breves_france],
        "arnaque": {
            "alerte": {"titre": alerte.titre, "source": alerte.source, "lien": alerte.lien,
                       "resume": couper(alerte.texte_source, LONGUEUR_BREVE)} if alerte else None,
            "fiche": None,  # fiche de la bibliothèque Arnaques associée par mots-clés : étape 7
        },
    }


def _breve(article: Article) -> dict:
    return {"titre": article.titre, "resume": couper(article.texte_source, LONGUEUR_BREVE),
            "source": article.source, "langue": article.langue, "lien": article.lien}


# --- Outils --------------------------------------------------------------------------

def niveau(score: float | None) -> str:
    """Niveau de menace selon les seuils CVSS officiels."""
    if not score:
        return "inconnu"
    if score >= 9:
        return "critique"
    if score >= 7:
        return "haute"
    if score >= 4:
        return "moyenne"
    return "faible"


def article_reference(faille: Faille) -> Article:
    """L'article le plus officiel qui cite la faille : CERT-FR (alerte d'abord), puis CISA, puis presse."""
    def rang(article: Article) -> int:
        if article.source == "CERT-FR":
            return 0 if article.details.get("categorie") == "alerte" else (2 if est_avis(article) else 1)
        if article.source == "CISA KEV":
            return 3
        return 4 if article.langue == "fr" else 5
    candidats = faille.articles + ([faille.kev] if faille.kev else [])
    return min(candidats, key=rang)


def nom_produit(faille: Faille) -> str:
    if faille.kev:
        editeur, produit = faille.kev.details.get("editeur", ""), faille.kev.details.get("produit", "")
        nom = produit if produit.lower().startswith(editeur.lower()) else f"{editeur} {produit}"
        if nom.strip():
            return nom.strip()
    if faille.nvd and faille.nvd.produits:
        return faille.nvd.produits[0]
    return "Produit non précisé"


def lien_nvd(cve: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve}"


def virgule(nombre) -> str:
    return str(nombre).replace(".", ",")


def couper(texte: str, longueur: int) -> str:
    """Coupe un texte trop long à la fin d'un mot et ajoute « … »."""
    if len(texte) <= longueur:
        return texte
    return texte[:longueur].rsplit(" ", 1)[0].rstrip(",;:.") + "…"
