"""
Réglages de TRACES.
Tout ce qui peut changer (chemins, délais, clés) est ici, pas dans le code.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

# --- Chemins ------------------------------------------------------------------

RACINE = Path(__file__).parent
DOSSIER_DATA = RACINE / "data"
DOSSIER_SORTIE = RACINE / "sortie"
DOSSIER_BIBLIOTHEQUES = RACINE / "bibliotheques"
FICHIER_DEJA_VUS = DOSSIER_DATA / "deja_vus.json"

# --- Secrets (lus dans .env) --------------------------------------------------

load_dotenv(RACINE / ".env")  # ne fait rien si .env n'existe pas
NVD_API_KEY = os.getenv("NVD_API_KEY", "").strip()

# --- Politesse envers les sites -----------------------------------------------

USER_AGENT = "TRACES-veille-etudiant/3.0 (projet pedagogique)"
TIMEOUT = 15            # secondes avant d'abandonner une requête
DELAI_REQUETES = 2      # secondes d'attente entre deux requêtes au même site

# --- Sources (adresses vérifiées le 2026-11-03) ---------------------------------

AGE_MAX_JOURS = 30      # on ignore les articles plus anciens

# Le CERT-FR a déménagé de cert.ssi.gouv.fr vers cert.cyber.gouv.fr (l'ancienne adresse redirige)
CERTFR_FLUX = {
    "alerte":    "https://cert.cyber.gouv.fr/alerte/feed/",     # failles graves, souvent exploitées
    "avis":      "https://cert.cyber.gouv.fr/avis/feed/",       # nombreux : jamais en une
    "actualite": "https://cert.cyber.gouv.fr/actualite/feed/",  # bulletins d'actualité
    "cti":       "https://cert.cyber.gouv.fr/cti/feed/",        # rapports de menace
}

CYBERMALVEILLANCE_FLUX = "https://www.cybermalveillance.gouv.fr/feed/atom-flux-actualites"

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

PRESSE = [
    {"nom": "BleepingComputer", "langue": "en", "url": "https://www.bleepingcomputer.com/feed/"},
    {"nom": "The Hacker News",  "langue": "en", "url": "https://feeds.feedburner.com/TheHackersNews"},
    {"nom": "Zataz",            "langue": "fr", "url": "https://www.zataz.com/feed/"},
    # LeMagIT n'a pas de flux dédié à la sécurité : on filtre son flux général par
    # mots-clés dans le TITRE (début de mot : "vulnérabilit" trouve "vulnérabilités")
    {"nom": "LeMagIT", "langue": "fr", "url": "https://www.lemagit.fr/rss/ContentSyndication.xml",
     "mots_cles": ["cyber", "sécurit", "vulnérabilit", "faille", "attaqu", "ransomware", "chiffrement",
                   "rançongiciel", "malware", "logiciel malveillant", "phishing", "hameçonnage",
                   "piratage", "pirate", "fuite de données", "CVE", "menace", "SOC "]},
]
