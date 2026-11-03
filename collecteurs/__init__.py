"""
Collecteurs : un module par source, tous renvoient une liste d'Article.
collecter_tout() les lance un par un et rassemble le résultat.
"""

import logging
from datetime import datetime, timedelta, timezone

import config

from . import certfr, cisa_kev, cybermalveillance, presse
from .article import Article

log = logging.getLogger(__name__)

COLLECTEURS = {
    "CERT-FR": certfr.collecter,
    "Cybermalveillance": cybermalveillance.collecter,
    "CISA KEV": cisa_kev.collecter,
    "Presse": presse.collecter,
}

DATE_INCONNUE = datetime.min.replace(tzinfo=timezone.utc)


def collecter_tout() -> list[Article]:
    """Articles récents de toutes les sources, du plus récent au plus ancien."""
    limite = datetime.now(timezone.utc) - timedelta(days=config.AGE_MAX_JOURS)
    tous = []
    for nom, collecter in COLLECTEURS.items():
        try:
            articles = collecter()
        except Exception:
            # Une source cassée ne doit pas empêcher le numéro de sortir
            log.exception("[%s] erreur inattendue, source ignorée pour aujourd'hui", nom)
            continue
        recents = [a for a in articles if a.date is None or a.date >= limite]
        log.info("[%s] %d articles récents (sur %d lus)", nom, len(recents), len(articles))
        tous += recents

    tous.sort(key=lambda a: a.date or DATE_INCONNUE, reverse=True)
    return tous
