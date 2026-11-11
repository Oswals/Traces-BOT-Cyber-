"""
Vidéo explicative d'un épisode : un lien saisi à la main dans le fichier de l'épisode
("video": {"titre", "auteur", "lien"}), vérifié avant affichage.

On ne cherche PAS de vidéo automatiquement : sans liste de chaînes de confiance, on
risquerait de renvoyer vers n'importe quoi. Un lien qui ne répond plus n'est pas affiché.

Pour YouTube, on interroge « oEmbed » : une petite adresse officielle qui répond 200 avec le
titre si la vidéo existe, et 404 sinon. Pas de clé d'API nécessaire. Pour les autres sites,
une simple requête HEAD (l'en-tête seul, sans télécharger la page).
"""

import logging
from urllib.parse import urlparse

import requests

import config

log = logging.getLogger(__name__)

OEMBED_YOUTUBE = "https://www.youtube.com/oembed"
SITES_YOUTUBE = {"www.youtube.com", "youtube.com", "youtu.be", "m.youtube.com"}


def verifier_video(video: dict | None) -> dict | None:
    """Renvoie la vidéo si son lien répond, None sinon (ou si le champ est vide ou mal formé)."""
    if not video or not isinstance(video, dict):
        return None
    lien = str(video.get("lien", "")).strip()
    if not lien.lower().startswith("https://") or not video.get("titre"):
        return None
    entetes = {"User-Agent": config.USER_AGENT}
    try:
        if urlparse(lien).netloc in SITES_YOUTUBE:
            reponse = requests.get(OEMBED_YOUTUBE, params={"url": lien, "format": "json"},
                                   headers=entetes, timeout=config.TIMEOUT)
        else:
            reponse = requests.head(lien, headers=entetes, timeout=config.TIMEOUT, allow_redirects=True)
    except requests.RequestException as erreur:
        log.warning("Vidéo non vérifiable (%s) : non affichée. %s", lien, erreur)
        return None
    if not reponse.ok:
        log.warning("Vidéo introuvable (HTTP %s) : non affichée. %s", reponse.status_code, lien)
        return None
    return {"titre": str(video["titre"]), "auteur": str(video.get("auteur", "")), "lien": lien}
