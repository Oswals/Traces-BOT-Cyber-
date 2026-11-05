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

# Cybermalveillance.gouv.fr n'est PLUS interrogé : son anti-robot (Imperva) bloque les accès
# automatiques. La rubrique Arnaques a sa propre logique, voir plus bas.

# Bulletin complet de chaque alerte / avis : adresse du bulletin + "json/" (export officiel)
FICHIER_CACHE_CERTFR = DOSSIER_DATA / "cache_certfr.json"
CERTFR_CACHE_JOURS = 2  # un bulletin peut être mis à jour (nouvelles CVE) : on le relit après 2 jours

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# --- NVD (dictionnaire des CVE, jamais une source d'articles) --------------------

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
# Limites officielles : 5 requêtes / 30 s sans clé, 50 / 30 s avec clé (+ marge)
NVD_DELAI_SANS_CLE = 6.5
NVD_DELAI_AVEC_CLE = 0.7
FICHIER_CACHE_NVD = DOSSIER_DATA / "cache_nvd.json"
NVD_CACHE_JOURS = 7     # au-delà, on redemande la CVE (son score a pu changer)

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

# --- Sélection et numéro --------------------------------------------------------

FENETRE_UNE_JOURS = 3       # la une et les failles exploitées sont choisies parmi les infos de moins de 3 jours
NB_FAILLES_EXPLOITEES = 3   # fiches de la page « Failles exploitées »
NB_BREVES = 4               # brèves par colonne (Monde, France)
FICHIER_NUMERO = DOSSIER_DATA / "numero.json"  # dernier numéro publié (pour numéroter le suivant)

# --- Rubrique « Arnaques » ---------------------------------------------------------
# Ordre de priorité : 1. alerte saisie à la main  2. article de presse  3. fiche en rotation

FICHIER_ARNAQUE_MANUELLE = DOSSIER_DATA / "arnaque_manuelle.json"  # modèle : arnaque_manuelle.exemple.json
ARNAQUE_MANUELLE_JOURS = 7   # au-delà, l'alerte saisie à la main est considérée comme périmée
ARNAQUE_PRESSE_JOURS = 7     # on cherche un article de presse sur une arnaque de moins de 7 jours
DOSSIER_ARNAQUES = DOSSIER_BIBLIOTHEQUES / "arnaques"
LIEN_CYBERMALVEILLANCE = "https://www.cybermalveillance.gouv.fr/"

# Mots-clés cherchés dans le TITRE des articles de presse (début de mot, sans accent obligatoire)
MOTS_CLES_ARNAQUE = ["arnaque", "escroc", "escroquerie", "hameçonnage", "hameconnage", "phishing",
                     "smishing", "vishing", "faux conseiller", "fausse conseillère", "faux support",
                     "faux site", "faux SMS", "sextorsion", "fraude au président", "usurpation", "scam"]
