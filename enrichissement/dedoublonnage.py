"""
Dédoublonnage par CVE : quand le CERT-FR, la CISA et la presse parlent de la
même faille, on obtient une seule Faille qui regroupe tous leurs articles.
"""

from collecteurs.article import Article

from .faille import Faille


def regrouper_par_cve(articles: list[Article]) -> dict[str, Faille]:
    """Une Faille par CVE citée. Un article qui cite 3 CVE apparaît dans 3 failles."""
    failles: dict[str, Faille] = {}
    for article in articles:
        for cve in article.cves:
            # setdefault : crée la Faille si la CVE est nouvelle, sinon renvoie l'existante
            failles.setdefault(cve, Faille(cve)).articles.append(article)
    return failles
