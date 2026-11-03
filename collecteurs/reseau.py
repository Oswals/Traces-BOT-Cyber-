"""
Téléchargement poli : User-Agent explicite, délai d'abandon, et pause entre
deux requêtes au même site. Tous les collecteurs passent par ici.
"""

import logging
import time
from urllib.parse import urlparse

import requests

import config

log = logging.getLogger(__name__)

# Heure du dernier appel à chaque site, pour respecter DELAI_REQUETES
_dernier_appel: dict[str, float] = {}


def telecharger(url: str, entetes: dict | None = None,
                delai: float = config.DELAI_REQUETES) -> bytes | None:
    """Renvoie le contenu de l'URL, ou None en cas d'échec (l'erreur est journalisée).

    entetes : en-têtes HTTP en plus du User-Agent (ex. la clé d'API de la NVD)
    delai   : pause minimale entre deux requêtes à ce site, en secondes
    """
    site = urlparse(url).netloc
    if site in _dernier_appel:
        attente = delai - (time.monotonic() - _dernier_appel[site])
        if attente > 0:
            log.debug("Pause de %.1f s avant %s", attente, site)
            time.sleep(attente)

    log.debug("Téléchargement de %s", url)
    try:
        reponse = requests.get(url, timeout=config.TIMEOUT,
                               headers={"User-Agent": config.USER_AGENT, **(entetes or {})})
        reponse.raise_for_status()  # lève une erreur si code 404, 500...
    except requests.RequestException as erreur:
        log.error("Impossible de télécharger %s : %s", url, erreur)
        return None
    finally:
        _dernier_appel[site] = time.monotonic()

    return reponse.content
