"""
Collecteur CISA KEV : catalogue officiel des failles activement exploitées.
C'est un fichier JSON (pas un flux RSS) : une entrée par CVE.

Le catalogue sert deux fois : ici (failles récemment ajoutées) et dans
l'enrichissement (savoir si une CVE citée ailleurs est exploitée). Il n'est
téléchargé qu'une fois par lancement.
"""

import json
import logging
from datetime import datetime, timezone

import config

from .article import Article
from .reseau import telecharger

log = logging.getLogger(__name__)

LIEN_CATALOGUE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search="

_catalogue: list[dict] | None = None  # gardé en mémoire après le premier téléchargement


def charger_catalogue() -> list[dict]:
    """Toutes les entrées du catalogue (liste vide si le téléchargement échoue)."""
    global _catalogue
    if _catalogue is not None:
        return _catalogue

    contenu = telecharger(config.CISA_KEV_URL)
    if contenu is None:
        return []
    try:
        _catalogue = json.loads(contenu).get("vulnerabilities", [])
    except json.JSONDecodeError as erreur:
        log.error("[CISA KEV] le fichier reçu n'est pas du JSON valide : %s", erreur)
        return []
    return _catalogue


def collecter() -> list[Article]:
    return [vers_article(faille) for faille in charger_catalogue()]


def vers_article(faille: dict) -> Article:
    """Transforme une entrée du catalogue en Article."""
    cve = faille.get("cveID", "")
    try:
        date = datetime.strptime(faille["dateAdded"], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except (KeyError, ValueError):
        date = None

    return Article(
        titre=faille.get("vulnerabilityName") or cve,
        lien=LIEN_CATALOGUE + cve,
        source="CISA KEV",
        type_source="base",
        date=date,  # date d'ajout au catalogue
        texte_source=faille.get("shortDescription", ""),
        cves=[cve] if cve else [],
        langue="en",
        details={
            "editeur": faille.get("vendorProject", ""),
            "produit": faille.get("product", ""),
            "action_requise": faille.get("requiredAction", ""),
            "echeance": faille.get("dueDate", ""),
            "rancongiciel": faille.get("knownRansomwareCampaignUse", ""),  # "Known" ou "Unknown"
            "cwes": faille.get("cwes", []),
        },
    )
