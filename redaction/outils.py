"""
Petits calculs sur une Faille, partagés par les rédacteurs et la mise en page.
"""

import re

from collecteurs.article import Article
from enrichissement.bulletins import Bulletin
from enrichissement.faille import Faille


def niveau(score: float | None) -> str:
    """Niveau de menace selon les seuils CVSS officiels."""
    if not score:
        return "inconnu"
    if score >= 9:
        return "critique"
    if score >= 7:
        return "haute"
    if score >= 4:
        return "moyenne"
    return "faible"


def _rang(article: Article) -> int:
    """Plus le rang est petit, plus l'article est officiel."""
    if article.source == "CERT-FR":
        return {"alerte": 0, "avis": 2}.get(article.details.get("categorie"), 1)
    if article.source == "CISA KEV":
        return 3
    return 4 if article.langue == "fr" else 5


def article_reference(faille: Faille) -> Article:
    """L'article le plus officiel qui cite la faille : CERT-FR (alerte d'abord), puis CISA, puis presse."""
    candidats = faille.articles + ([faille.kev] if faille.kev else [])
    return min(candidats, key=_rang)


def bulletin_certfr(faille: Faille) -> tuple[Bulletin, Article] | tuple[None, None]:
    """Le bulletin CERT-FR complet le plus pertinent (alerte avant avis), et son article.

    Un avis peut citer la CVE d'un composant tiers : l'avis Citrix cite une faille de la
    bibliothèque Brotli que Citrix embarque. Ses « systèmes affectés » seraient alors
    des produits Citrix, hors sujet. On ne garde donc un avis que s'il parle du produit.
    """
    pertinents = [a for a in faille.articles if "bulletin" in a.details
                  and (a.details.get("categorie") == "alerte" or _parle_du_produit(a, faille))]
    if not pertinents:
        return None, None
    article = min(pertinents, key=_rang)
    return article.details["bulletin"], article


def _parle_du_produit(article: Article, faille: Faille) -> bool:
    """Un mot du nom du produit (3 lettres ou plus) apparaît-il dans le titre ou les systèmes du bulletin ?"""
    if faille.kev and faille.kev.details.get("produit"):
        produit = faille.kev.details["produit"]
    elif faille.nvd and faille.nvd.produits:
        produit = faille.nvd.produits[0]
    else:
        return False
    bulletin = article.details["bulletin"]
    texte = (bulletin.titre + " " + " ".join(bulletin.systemes)).lower()
    return any(mot in texte for mot in re.findall(r"\w{3,}", produit.lower()))


def nom_produit(faille: Faille) -> str:
    if faille.kev:
        editeur, produit = faille.kev.details.get("editeur", ""), faille.kev.details.get("produit", "")
        nom = produit if produit.lower().startswith(editeur.lower()) else f"{editeur} {produit}"
        if nom.strip():
            return nom.strip()
    if faille.nvd and faille.nvd.produits:
        return faille.nvd.produits[0]
    return "Produit non précisé"


def lien_nvd(cve: str) -> str:
    return f"https://nvd.nist.gov/vuln/detail/{cve}"


def virgule(nombre) -> str:
    """9.8 -> "9,8"."""
    return str(nombre).replace(".", ",")


def couper(texte: str, longueur: int) -> str:
    """Coupe un texte trop long à la fin d'un mot et ajoute « … »."""
    # Beaucoup de flux RSS terminent leur résumé par « [...] » ou « […] » : on l'enlève
    texte = re.sub(r"\s*\[(?:\.\.\.|…)\]\s*$", "", texte)
    if len(texte) <= longueur:
        return texte
    return texte[:longueur].rsplit(" ", 1)[0].rstrip(",;:.") + "…"


def liste_fr(elements: list[str], maximum: int) -> str:
    """["a", "b", "c", "d"], 2 -> "a ; b ; et 2 autres"."""
    texte = " ; ".join(elements[:maximum])
    reste = len(elements) - maximum
    if reste > 0:
        texte += f" ; et {reste} autre{'s' if reste > 1 else ''}"
    return texte
