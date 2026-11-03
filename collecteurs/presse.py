"""
Collecteur presse : BleepingComputer, The Hacker News, Zataz, LeMagIT.
Ces sources se lisent toutes de la même façon (un flux RSS) : elles sont
décrites dans config.PRESSE plutôt que dupliquées en 4 fichiers identiques.
Si l'une demande un jour un traitement spécial, elle aura son propre fichier.
"""

import logging
import re

import config

from .article import Article
from .rss import lire_flux

log = logging.getLogger(__name__)


def collecter() -> list[Article]:
    articles = []
    for journal in config.PRESSE:
        lus = lire_flux(journal["url"], source=journal["nom"],
                        type_source="presse", langue=journal["langue"])
        mots_cles = journal.get("mots_cles")
        if mots_cles:  # flux généraliste : on ne garde que les articles cyber
            gardes = [a for a in lus if _parle_de(a, mots_cles)]
            log.debug("[%s] %d/%d articles gardés après filtre par mots-clés",
                      journal["nom"], len(gardes), len(lus))
            lus = gardes
        articles += lus
    return articles


def _parle_de(article: Article, mots_cles: list[str]) -> bool:
    # On ne regarde que le titre : le résumé d'un flux généraliste contient souvent
    # l'article entier, où un mot comme "sécurité" apparaît presque toujours.
    # \b = début de mot : "faille" trouve "failles" mais pas "défaillance"
    motif = r"\b(?:" + "|".join(re.escape(mot) for mot in mots_cles) + ")"
    return re.search(motif, article.titre, re.IGNORECASE) is not None
