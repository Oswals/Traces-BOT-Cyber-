"""
Enrichissement : lit les bulletins CERT-FR complets, regroupe les articles par
CVE, puis complète chaque faille avec la NVD (score CVSS, CWE, produits) et la
CISA KEV (exploitée ou non).
"""

import logging

from collecteurs.article import Article

from .bulletins import completer_bulletins
from .dedoublonnage import regrouper_par_cve
from .faille import Faille, FicheNVD
from .kev import index_kev
from .nvd import fiches_nvd

log = logging.getLogger(__name__)


def enrichir(articles: list[Article]) -> list[Faille]:
    """Failles citées dans les articles, exploitées d'abord, puis par score décroissant."""
    kev = index_kev()
    # Les bulletins JSON du CERT-FR complètent les CVE des articles : à faire AVANT le regroupement
    deja_citees = {cve for article in articles for cve in article.cves}
    completer_bulletins(articles, cves_connues=set(kev) | deja_citees)

    failles = regrouper_par_cve(articles)
    fiches = fiches_nvd(sorted(failles))

    for cve, faille in failles.items():
        faille.kev = kev.get(cve)
        faille.nvd = fiches.get(cve)

    log.info("[Enrichissement] %d failles, dont %d exploitées et %d sans fiche NVD",
             len(failles), sum(f.exploitee for f in failles.values()),
             sum(f.nvd is None for f in failles.values()))
    return sorted(failles.values(), key=_priorite, reverse=True)


def _priorite(faille: Faille) -> tuple:
    # Python compare les tuples case par case : d'abord exploitée (True > False), puis le score
    return (faille.exploitee, faille.score or 0)
