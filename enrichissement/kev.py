"""
CISA KEV comme dictionnaire : pour une CVE donnée, est-elle activement exploitée ?
On interroge le catalogue COMPLET, pas seulement les ajouts récents : une faille
citée aujourd'hui par le CERT-FR peut être dans le catalogue depuis des mois.
"""

from collecteurs import cisa_kev
from collecteurs.article import Article


def index_kev() -> dict[str, Article]:
    """Dictionnaire CVE -> entrée du catalogue CISA KEV."""
    index = {}
    for entree in cisa_kev.charger_catalogue():
        article = cisa_kev.vers_article(entree)
        if article.cves:
            index[article.cves[0]] = article
    return index
