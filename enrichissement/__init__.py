"""
Enrichissement : regroupe les articles par CVE, puis complète chaque faille
avec la NVD (score CVSS, CWE, produits) et la CISA KEV (exploitée ou non).
"""

import logging

from collecteurs.article import Article

from .dedoublonnage import regrouper_par_cve
from .faille import Faille, FicheNVD
from .kev import index_kev
from .nvd import fiches_nvd

log = logging.getLogger(__name__)


def enrichir(articles: list[Article]) -> list[Faille]:
    """Failles citées dans les articles, exploitées d'abord, puis par score décroissant."""
    failles = regrouper_par_cve(articles)
    kev = index_kev()
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
