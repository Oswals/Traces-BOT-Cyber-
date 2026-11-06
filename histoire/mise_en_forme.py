"""
Transforme le choix du jour (histoire/choix.py) en données pour le gabarit histoire.html.

Trois présentations :
- « complet »    : épisode rédigé et validé, double page, avec chronologie et schéma ;
- « découverte » : grand événement sans épisode, seulement ce que dit Wikipédia
                   (rubriques vides masquées), double page s'il y a assez de texte, sinon une page ;
- « technique »  : événement moyen, une page : résumé de la source, CVE avec profil CVSS,
                   techniques ATT&CK.
"""

import logging
from datetime import date

from enrichissement.nvd import fiches_nvd
from mise_en_page.assemblage import MOIS, date_fr
from redaction import cvss
from redaction.outils import lien_nvd, niveau
from redaction.sans_ia import glossaire

from . import extraits

log = logging.getLogger(__name__)

LONGUEUR_SECTION_DOUBLE = 480   # caractères par rubrique sur une double page
LONGUEUR_SECTION_SIMPLE = 380   # ... sur une seule page
LONGUEUR_RESUME_TECHNIQUE = 700
TEXTE_MIN_DOUBLE = 1500         # en dessous, la fiche découverte tient sur une page
NB_TECHNIQUES = 12              # techniques ATT&CK affichées (les autres : lien vers la campagne)
NB_CVE = 2
ATTRIBUTION_ATTACK = "© The MITRE Corporation. Reproduit avec l'autorisation de The MITRE Corporation."

ENVERGURES = {"grand": "Grand événement", "moyen": "Événement moyen"}

# Toutes les clés lues par le gabarit, avec leur valeur quand un type de fiche ne les remplit pas
DEFAUTS = {"double": False, "verifie": False, "langue": "fr", "texte_indisponible": False,
           "chapeau": {"texte": "", "langue": "fr"}, "sections": [], "chronologie": [], "schema": [],
           "lexique": [], "reperes": [], "sources": [], "cves": [], "techniques": [],
           "techniques_reste": 0, "attribution": "", "licence": ""}


def phrase_date(c: dict) -> str:
    """« Survenu le 12 mai 2017 », « Révélé le 7 septembre 2017 », « Survenu en mai 2017 »..."""
    verbe = "Révélé" if c.get("type_date") == "revelation" else "Survenu"
    texte = date_affichee(c["date"], c.get("precision_date", "année"))
    return f"{verbe} {'le' if c.get('precision_date') == 'jour' else 'en'} {texte}"


def date_affichee(date_iso: str, precision: str) -> str:
    annee, mois = int(date_iso[:4]), int(date_iso[5:7])
    if precision == "jour":
        return date_fr(date.fromisoformat(date_iso))
    if precision == "mois":
        return f"{MOIS[mois - 1]} {annee}"
    return str(annee)


def preparer(choix: dict | None, jour: date) -> dict | None:
    if not choix:
        return None
    c = choix["candidat"]
    base = {
        "type": choix["type"],
        "titre": c["titre"],
        "annee": c["date"][:4],
        "date": phrase_date(c),
        "categorie": c["categorie"],
        "envergure": ENVERGURES.get(c.get("envergure"), ""),
        "anniversaire": (f"Il y a {jour.year - int(c['date'][:4])} ans, jour pour jour"
                         if choix.get("anniversaire") else ""),
        "lien_source": c.get("lien", ""),
    }
    if choix["type"] == "complet":
        return {**base, **page_episode(c)}
    if choix["type"] == "découverte":
        return {**base, **_decouverte(c)}
    return {**base, **_technique(c)}


# --- Épisode complet ------------------------------------------------------------------

def page_episode(episode: dict, avec_cves: bool = True) -> dict:
    """avec_cves=False : sans appel à la NVD (numéro de démonstration, hors ligne)."""
    return {**DEFAUTS,
        "double": True,
        "verifie": episode.get("verifie") is True,
        "chapeau": {"texte": episode["chapeau"], "langue": "fr"},
        "sections": [{**s, "langue": "fr"} for s in episode["sections"] if s.get("texte")],
        "chronologie": episode.get("chronologie", []),
        "schema": episode.get("schema", []),
        "lexique": episode.get("lexique", []),
        "sources": episode.get("sources", []),
        "cves": _cves(episode.get("cves", [])) if avec_cves else [],
    }


# --- Fiche découverte -----------------------------------------------------------------------

def _decouverte(c: dict) -> dict:
    texte = extraits.texte_article(c["lien"]) if c.get("source") == "Wikipédia" else None
    chapeau, sections = "", []
    if texte:
        _, brut = extraits.rubriques(texte, 10_000)
        double = sum(len(s["texte"]) for s in brut) >= TEXTE_MIN_DOUBLE and len(brut) >= 4
        chapeau, sections = extraits.rubriques(texte, LONGUEUR_SECTION_DOUBLE if double else LONGUEUR_SECTION_SIMPLE)
    else:
        double = False
    langue = c.get("langue", "fr")
    sources = [{"titre": f"Wikipédia ({langue.upper()}), « {c['titre']} », CC BY-SA 4.0", "lien": c["lien"]}]
    if c.get("lien_en") and c["lien_en"] != c["lien"]:
        sources.append({"titre": f"Wikipédia (EN), « {c['titre_en']} »", "lien": c["lien_en"]})
    reperes = [("Catégorie", c["categorie"].capitalize())]
    if c.get("langues"):
        reperes.append(("Notoriété", f"article présent dans {c['langues']} langues"))
    if c.get("cves"):
        reperes.append(("CVE", ", ".join(c["cves"][:3])))
    return {**DEFAUTS,
        "double": double,
        "chapeau": {"texte": chapeau, "langue": langue},
        "sections": [{**s, "langue": langue} for s in sections],
        "reperes": reperes,
        "sources": sources,
        "licence": "CC BY-SA 4.0",
        "langue": langue,
        "texte_indisponible": not texte,
        "cves": _cves(c.get("cves", [])),
    }


# --- Fiche technique (événement moyen) ----------------------------------------------------

def _technique(c: dict) -> dict:
    resume, langue = c.get("resume", ""), c.get("langue", "en")
    if not resume and c.get("source") == "Wikipédia":
        texte = extraits.texte_article(c["lien"])
        resume = extraits.decouper(texte)[0] if texte else ""
    techniques = c.get("techniques", [])
    source = c.get("source", "")
    return {**DEFAUTS,
        "resume": {"texte": extraits.couper_phrases(resume, LONGUEUR_RESUME_TECHNIQUE), "langue": langue,
                   "source": source + (" (CC BY-SA 4.0)" if source == "Wikipédia" else ""),
                   "lien": c.get("lien", "")},
        "cves": _cves(c.get("cves", [])),
        "techniques": techniques[:NB_TECHNIQUES],
        "techniques_reste": max(0, len(techniques) - NB_TECHNIQUES),
        "attribution": ATTRIBUTION_ATTACK if source == "MITRE ATT&CK" else "",
        "reperes": [("Catégorie", c["categorie"].capitalize()), ("Source", source)],
        "sources": [{"titre": f"{source} · {c['titre']}", "lien": c.get("lien", "")}],
    }


def _cves(cves: list[str]) -> list[dict]:
    """CVE avec score, niveau, profil CVSS (8 cases) et type de faille, depuis la NVD."""
    if not cves:
        return []
    fiches = fiches_nvd(cves[:NB_CVE])
    resultat = []
    for cve in cves[:NB_CVE]:
        fiche = fiches.get(cve)
        types = [f"{cwe} · {glossaire()[cwe]['nom']}" if cwe in glossaire() else cwe
                 for cwe in (fiche.cwes if fiche else [])]
        resultat.append({
            "cve": cve, "lien": lien_nvd(cve),
            "score": fiche.score if fiche else None, "niveau": niveau(fiche.score if fiche else None),
            "version": fiche.version_cvss if fiche else "",
            "profil": cvss.profil(fiche.vecteur) if fiche else [],
            "type": ", ".join(types[:2]) or "type non précisé par la NVD",
            "produits": ", ".join((fiche.produits if fiche else [])[:3]),
        })
    return resultat
