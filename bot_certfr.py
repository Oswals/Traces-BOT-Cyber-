"""
Bot de veille CERT-FR (ANSSI)
Récupère les dernières publications et n'affiche que les nouveautés.

Utilisation :
    python bot_certfr.py              -> nouveautés de tous les flux
    python bot_certfr.py --flux alerte -> un seul flux
    python bot_certfr.py --tout       -> tout afficher (même déjà vu)
    python bot_certfr.py --debug      -> messages détaillés pour déboguer
"""

import argparse
import json
import logging
import re
from pathlib import Path

import feedparser
import requests

# --- Configuration -----------------------------------------------------------

FLUX = {
    "alerte":    "https://www.cert.ssi.gouv.fr/alerte/feed/",     # failles graves, souvent exploitées
    "avis":      "https://www.cert.ssi.gouv.fr/avis/feed/",       # vulnérabilités + correctifs
    "actualite": "https://www.cert.ssi.gouv.fr/actualite/feed/",  # bulletins d'actualité
    "cti":       "https://www.cert.ssi.gouv.fr/cti/feed/",        # rapports de menace
}

FICHIER_VUS = Path(__file__).parent / "deja_vus.json"  # mémoire du bot
TIMEOUT = 15  # secondes avant d'abandonner une requête

log = logging.getLogger("bot")


# --- Mémoire : ce qu'on a déjà vu ---------------------------------------------

def charger_vus() -> set:
    if not FICHIER_VUS.exists():
        log.debug("Pas encore de fichier %s, on part de zéro", FICHIER_VUS.name)
        return set()
    try:
        return set(json.loads(FICHIER_VUS.read_text(encoding="utf-8")))
    except json.JSONDecodeError:
        log.warning("%s est corrompu, on le réinitialise", FICHIER_VUS.name)
        return set()


def sauver_vus(vus: set) -> None:
    FICHIER_VUS.write_text(json.dumps(sorted(vus), indent=2), encoding="utf-8")


# --- Récupération d'un flux ----------------------------------------------------

def recuperer_flux(nom: str, url: str) -> list[dict]:
    log.debug("Téléchargement de %s (%s)", nom, url)
    try:
        reponse = requests.get(url, timeout=TIMEOUT,
                               headers={"User-Agent": "bot-veille-etudiant/1.0"})
        reponse.raise_for_status()  # lève une erreur si code 404, 500...
    except requests.RequestException as erreur:
        log.error("[%s] impossible de récupérer le flux : %s", nom, erreur)
        return []

    flux = feedparser.parse(reponse.content)
    if flux.bozo:  # feedparser signale un XML mal formé
        log.warning("[%s] flux mal formé : %s", nom, flux.bozo_exception)

    publications = []
    for entree in flux.entries:
        texte = entree.get("title", "") + " " + entree.get("summary", "")
        publications.append({
            "flux": nom,
            "id": entree.get("id") or entree.get("link"),
            "titre": entree.get("title", "(sans titre)"),
            "lien": entree.get("link", ""),
            "date": entree.get("published", "date inconnue"),
            "cves": sorted(set(re.findall(r"CVE-\d{4}-\d{4,7}", texte))),
        })
    log.debug("[%s] %d publications lues", nom, len(publications))
    return publications


# --- Affichage -----------------------------------------------------------------

def afficher(pub: dict) -> None:
    print(f"\n[{pub['flux'].upper()}] {pub['titre']}")
    print(f"  Date : {pub['date']}")
    print(f"  Lien : {pub['lien']}")
    if pub["cves"]:
        print(f"  CVE  : {', '.join(pub['cves'])}")


# --- Programme principal ------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Veille CERT-FR")
    parser.add_argument("--flux", choices=FLUX.keys(), help="un seul flux")
    parser.add_argument("--tout", action="store_true", help="ignorer la mémoire")
    parser.add_argument("--debug", action="store_true", help="logs détaillés")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(levelname)s: %(message)s")

    flux_choisis = {args.flux: FLUX[args.flux]} if args.flux else FLUX
    vus = charger_vus()
    nouveautes = 0

    for nom, url in flux_choisis.items():
        for pub in recuperer_flux(nom, url):
            if args.tout or pub["id"] not in vus:
                afficher(pub)
                nouveautes += 1
            vus.add(pub["id"])

    sauver_vus(vus)
    print(f"\n{nouveautes} publication(s) affichée(s).")


if __name__ == "__main__":
    main()
