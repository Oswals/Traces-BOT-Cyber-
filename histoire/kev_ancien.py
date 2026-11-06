"""
Anciennes failles du catalogue CISA KEV, candidates « événement moyen » (catégorie CYBERATTAQUE :
elles ont été exploitées dans la réalité).

On ne garde que des CVE d'au moins KEV_AGE_MIN_ANS ans. Le filtre de gravité (CVSS >= 9
ou usage connu par un rançongiciel) et la date exacte de publication viennent de la NVD,
à l'étape suivante (7b) : ici, on regarde seulement l'année inscrite dans le numéro de CVE.
"""

import re
from datetime import date

import config
from collecteurs.cisa_kev import charger_catalogue

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
