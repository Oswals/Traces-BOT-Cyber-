"""
Collecteur CISA KEV : catalogue officiel des failles activement exploitées.
C'est un fichier JSON (pas un flux RSS) : une entrée par CVE.
"""

import json
import logging
from datetime import datetime, timezone

import config

from .article import Article
from .reseau import telecharger

log = logging.getLogger(__name__)

LIEN_CATALOGUE = "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search="


def collecter() -> list[Article]:
    contenu = telecharger(config.CISA_KEV_URL)
    if contenu is None:
        return []
    try:
        catalogue = json.loads(contenu)
    except json.JSONDecodeError as erreur:
        log.error("[CISA KEV] le fichier reçu n'est pas du JSON valide : %s", erreur)
        return []

    return [_vers_article(faille) for faille in catalogue.get("vulnerabilities", [])]


def _vers_article(faille: dict) -> Article:
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
