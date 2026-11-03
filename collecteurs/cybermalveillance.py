"""
Collecteur Cybermalveillance.gouv.fr, pour la rubrique « L'arnaque du moment ».
On lit le flux « actualités » : le flux « alertes » n'a ni résumé ni titre précis.
"""

import config

from .article import Article
from .rss import lire_flux


def collecter() -> list[Article]:
    return lire_flux(config.CYBERMALVEILLANCE_FLUX, source="Cybermalveillance",
                     type_source="officiel", langue="fr")
