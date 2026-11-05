"""
Sélection : choisit ce qui entre dans le numéro du jour.
  - la une : une faille importante et récente (jamais choisie à cause d'un simple « avis » CERT-FR)
  - les failles exploitées : les plus graves du catalogue CISA, hors une
  - les brèves Monde (presse en anglais) et France (presse en français)
  - la rubrique Arnaques (voir selection/arnaque.py)

Ce module ne rédige rien : il choisit. La mise en forme est faite par mise_en_page.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import config
from collecteurs.article import Article
from enrichissement.faille import Faille
from redaction.outils import nom_produit

from .arnaque import ChoixArnaque, choisir_arnaque

log = logging.getLogger(__name__)

DATE_INCONNUE = datetime.min.replace(tzinfo=timezone.utc)


@dataclass
class Selection:
    une: Faille
    failles: list[Faille]            # failles exploitées en fiches (page 4)
    breves_monde: list[Article]
    breves_france: list[Article]
    arnaque: ChoixArnaque            # jamais vide (au pire : la fiche du numéro)


def selectionner(articles: list[Article], failles: list[Faille], numero: int) -> Selection:
    if not failles:
        raise ValueError("Aucune faille collectée : impossible de composer la une. "
                         "Vérifie la connexion Internet (lance avec --debug pour le détail).")

    une = choisir_une(failles)
    exploitees = choisir_failles_exploitees(failles, exclure=une)
    arnaque = choisir_arnaque(articles, numero)
    # L'article choisi pour la rubrique Arnaques n'est pas répété dans les brèves
    lien_arnaque = arnaque.alerte["lien"] if arnaque.alerte else None
    presse = [a for a in articles if a.type_source == "presse" and a.lien != lien_arnaque]

    log.info("[Sélection] une : %s · %d failles exploitées · arnaques : %s",
             une.cve, len(exploitees), arnaque.mode)
    return Selection(
        une=une,
        failles=exploitees,
        breves_monde=_varier([a for a in presse if a.langue == "en"], config.NB_BREVES),
        breves_france=_varier([a for a in presse if a.langue == "fr"], config.NB_BREVES),
        arnaque=arnaque,
    )


# --- La une ---------------------------------------------------------------------

def choisir_une(failles: list[Faille]) -> Faille:
    # Règle de CLAUDE.md : les avis CERT-FR sont trop nombreux pour faire la une.
    # Une faille n'est candidate que si au moins une source autre qu'un avis la cite.
    candidates = [f for f in failles if any(not est_avis(a) for a in f.articles)] or failles
    candidates = _recentes(candidates, config.FENETRE_UNE_JOURS) or candidates
    return max(candidates, key=_priorite_une)


def _priorite_une(faille: Faille) -> tuple:
    # Comparaison case par case : alerte CERT-FR d'abord, puis exploitée, score, nombre de sources
    alerte = any(a.source == "CERT-FR" and a.details.get("categorie") == "alerte"
                 for a in faille.articles)
    return (alerte, faille.exploitee, faille.score or 0, len(faille.sources), date_recente(faille))


# --- Les failles exploitées -----------------------------------------------------

def choisir_failles_exploitees(failles: list[Faille], exclure: Faille) -> list[Faille]:
    exploitees = [f for f in failles if f.exploitee and f.cve != exclure.cve]
    tri = lambda f: (f.score or 0, date_recente(f))
    # On prend d'abord les failles récentes, et on complète avec les plus anciennes si besoin
    recentes = sorted(_recentes(exploitees, config.FENETRE_UNE_JOURS), key=tri, reverse=True)
    cves_recentes = {f.cve for f in recentes}
    autres = sorted([f for f in exploitees if f.cve not in cves_recentes], key=tri, reverse=True)

    # Un produit n'apparaît qu'une fois dans le numéro : une alerte PHP qui cite deux CVE
    # ne doit pas donner la une ET une fiche sur PHP
    choisies, produits_vus = [], {nom_produit(exclure)}
    for faille in recentes + autres:
        produit = nom_produit(faille)
        if produit not in produits_vus:
            choisies.append(faille)
            produits_vus.add(produit)
        if len(choisies) == config.NB_FAILLES_EXPLOITEES:
            break
    return choisies


# --- Outils ---------------------------------------------------------------------

def est_avis(article: Article) -> bool:
    return article.source == "CERT-FR" and article.details.get("categorie") == "avis"


def date_recente(faille: Faille) -> datetime:
    """Date de l'article le plus récent qui cite la faille."""
    return max((a.date for a in faille.articles if a.date), default=DATE_INCONNUE)


def _recentes(failles: list[Faille], jours: int) -> list[Faille]:
    limite = datetime.now(timezone.utc) - timedelta(days=jours)
    return [f for f in failles if date_recente(f) >= limite]


def _varier(articles: list[Article], nombre: int) -> list[Article]:
    """Les articles les plus récents, en alternant les sources (pas 3 brèves du même journal)."""
    par_source: dict[str, list[Article]] = {}
    for article in articles:  # déjà triés du plus récent au plus ancien
        par_source.setdefault(article.source, []).append(article)

    choisis = []
    while len(choisis) < nombre and any(par_source.values()):
        for liste in par_source.values():  # un tour : le plus récent de chaque source
            if liste and len(choisis) < nombre:
                choisis.append(liste.pop(0))
    return choisis
