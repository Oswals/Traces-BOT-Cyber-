"""
Anciennes failles du catalogue CISA KEV, candidates « événement moyen » (catégorie CYBERATTAQUE :
elles ont été exploitées dans la réalité).

On ne garde ici que des CVE d'au moins KEV_AGE_MIN_ANS ans, d'après l'année inscrite dans
leur numéro. Le score CVSS et la date exacte de publication viennent ensuite de la NVD
(voir histoire/catalogue.py).
"""

import re
from datetime import date

import config
from collecteurs.cisa_kev import LIEN_CATALOGUE, charger_catalogue

MOTIF_ANNEE = re.compile(r"^CVE-(\d{4})-\d+$")


def anciennes_failles(aujourd_hui: date | None = None) -> list[dict]:
    """Entrées du catalogue dont la CVE a au moins KEV_AGE_MIN_ANS ans (d'après son numéro)."""
    aujourd_hui = aujourd_hui or date.today()
    annee_max = aujourd_hui.year - config.KEV_AGE_MIN_ANS
    resultat = []
    for faille in charger_catalogue():
        trouve = MOTIF_ANNEE.match(faille.get("cveID", ""))
        if not trouve or not config.HISTOIRE_ANNEE_MIN <= int(trouve.group(1)) <= annee_max:
            continue
        resultat.append({
            "cve": faille["cveID"],
            "titre": faille.get("vulnerabilityName") or faille["cveID"],
            "produit": f"{faille.get('vendorProject', '')} {faille.get('product', '')}".strip(),
            "rancongiciel": faille.get("knownRansomwareCampaignUse") == "Known",
            "ajout_kev": faille.get("dateAdded"),
            "resume": faille.get("shortDescription", ""),
        })
    return resultat
