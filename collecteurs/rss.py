"""
Lecture générique d'un flux RSS ou Atom, utilisée par les collecteurs.
"""

import logging
from datetime import datetime, timezone

import feedparser

from .article import Article, nettoyer_html
from .reseau import telecharger

log = logging.getLogger(__name__)


def lire_flux(url: str, source: str, type_source: str, langue: str,
              details: dict | None = None) -> list[Article]:
    """Télécharge un flux et transforme chaque entrée en Article."""
    contenu = telecharger(url)
    if contenu is None:
        return []

    flux = feedparser.parse(contenu)
    if flux.bozo:  # feedparser signale un XML mal formé (il lit quand même ce qu'il peut)
        log.warning("[%s] flux mal formé : %s", source, flux.bozo_exception)

    articles = []
    for entree in flux.entries:
        articles.append(Article(
            titre=nettoyer_html(entree.get("title", "")) or "(sans titre)",
            lien=entree.get("link", ""),
            source=source,
            type_source=type_source,
            date=_date_entree(entree),
            texte_source=nettoyer_html(entree.get("summary", "")),
            langue=langue,
            details=dict(details or {}),  # copie, pour ne pas partager le même dict
        ))
    log.debug("[%s] %d entrées lues dans %s", source, len(articles), url)
    return articles


def _date_entree(entree) -> datetime | None:
    # feedparser fournit la date déjà convertie en UTC
    date = entree.get("published_parsed") or entree.get("updated_parsed")
    if not date:
        return None
    return datetime(*date[:6], tzinfo=timezone.utc)
