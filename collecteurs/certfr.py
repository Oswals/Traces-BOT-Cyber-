"""
Collecteur CERT-FR (ANSSI) : alertes, avis, bulletins d'actualité, rapports CTI.
La catégorie est gardée dans details["categorie"] pour que la sélection
puisse écarter les avis de la une.
"""

import config

from .article import Article
from .rss import lire_flux


def collecter() -> list[Article]:
    articles = []
    for categorie, url in config.CERTFR_FLUX.items():
        articles += lire_flux(url, source="CERT-FR", type_source="officiel",
                              langue="fr", details={"categorie": categorie})
    return articles
