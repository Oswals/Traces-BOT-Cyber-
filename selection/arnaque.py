"""
Choix de la rubrique « Arnaques ». Cybermalveillance.gouv.fr bloque les accès
automatiques : on ne l'interroge plus. Ordre de priorité :

  1. data/arnaque_manuelle.json, s'il existe et date de moins de 7 jours
     (une alerte recopiée à la main, modèle : arnaque_manuelle.exemple.json)
  2. sinon, l'article de presse récent le plus récent dont le titre parle d'arnaque,
     associé à la fiche de la bibliothèque la plus proche (étiquette SOURCE)
  3. sinon, « La fiche du numéro » : une fiche de la bibliothèque, en rotation
     (étiquette BIBLIOTHÈQUE)

La rubrique n'est jamais vide : si la bibliothèque est illisible, une fiche de
secours écrite ici prend le relais.
"""

import json
import logging
import re
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone

import config
from collecteurs.article import Article

log = logging.getLogger(__name__)

CHAMPS_FICHE = ("id", "nom", "resume", "signes", "reflexe", "si_victime", "signaler", "mots_cles", "lien")
FICHE_PAR_DEFAUT = "hameconnage"  # quand aucun mot-clé ne départage les fiches

FICHE_SECOURS = {
    "id": "secours", "nom": "Reconnaître une arnaque en ligne", "verifie": True,
    "resume": "Les escroqueries en ligne jouent presque toujours sur l'urgence, la peur ou l'appât du gain.",
    "signes": ["Une demande pressante d'argent, de code ou de mot de passe.",
               "Un expéditeur ou un lien qui ne correspond pas à l'organisme officiel."],
    "reflexe": "Prendre le temps de vérifier par un autre moyen, sans utiliser le lien ou le numéro du message.",
    "si_victime": ["Contacter sa banque si des coordonnées bancaires ont été données, puis porter plainte."],
    "signaler": [{"nom": "Cybermalveillance.gouv.fr", "detail": "Conseils et assistance aux victimes.",
                  "lien": config.LIEN_CYBERMALVEILLANCE}],
    "mots_cles": [], "sources": [], "lien": config.LIEN_CYBERMALVEILLANCE,
}


@dataclass
class ChoixArnaque:
    mode: str               # "manuelle", "presse" ou "fiche" (fiche du numéro)
    fiche: dict             # fiche de la bibliothèque
    alerte: dict | None     # {"titre", "resume", "source", "lien", "langue", "date"} ; None en mode "fiche"


def choisir_arnaque(articles: list[Article], numero: int) -> ChoixArnaque:
    fiches = charger_fiches()

    alerte = alerte_manuelle()
    if alerte:
        fiche = _fiche_par_id(fiches, alerte.pop("fiche", "")) or fiche_la_plus_proche(
            alerte["titre"] + " " + alerte["resume"], fiches)
        log.info("[Arnaques] alerte saisie à la main · fiche : %s", fiche["id"])
        return ChoixArnaque("manuelle", fiche, alerte)

    article = article_presse(articles)
    if article:
        fiche = fiche_la_plus_proche(article.titre + " " + article.texte_source, fiches)
        log.info("[Arnaques] article de presse (%s) · fiche : %s", article.source, fiche["id"])
        return ChoixArnaque("presse", fiche, {
            "titre": article.titre, "resume": article.texte_source, "source": article.source,
            "lien": article.lien, "langue": article.langue, "date": article.date})

    fiche = fiches[numero % len(fiches)]  # rotation : une fiche différente à chaque numéro
    log.info("[Arnaques] pas d'alerte récente · fiche du numéro : %s", fiche["id"])
    return ChoixArnaque("fiche", fiche, None)


# --- 1. Alerte saisie à la main ----------------------------------------------------------

def alerte_manuelle() -> dict | None:
    """Contenu de data/arnaque_manuelle.json s'il est valide et récent, sinon None."""
    chemin = config.FICHIER_ARNAQUE_MANUELLE
    if not chemin.exists():
        return None
    try:
        donnees = json.loads(chemin.read_text(encoding="utf-8"))
    except json.JSONDecodeError as erreur:
        log.warning("[Arnaques] %s n'est pas du JSON valide (%s) : ignoré", chemin.name, erreur)
        return None
    if not (donnees.get("titre") and donnees.get("lien")):
        log.warning("[Arnaques] %s : les champs « titre » et « lien » sont obligatoires", chemin.name)
        return None

    # Date de l'alerte : champ "date" (AAAA-MM-JJ), sinon date de modification du fichier
    try:
        jour = date.fromisoformat(donnees["date"]) if donnees.get("date") else \
            datetime.fromtimestamp(chemin.stat().st_mtime).date()
    except ValueError:
        log.warning("[Arnaques] %s : date illisible %r (format attendu AAAA-MM-JJ)", chemin.name, donnees["date"])
        return None
    if (date.today() - jour).days > config.ARNAQUE_MANUELLE_JOURS:
        log.info("[Arnaques] alerte manuelle du %s périmée (plus de %d jours)", jour, config.ARNAQUE_MANUELLE_JOURS)
        return None

    return {"titre": donnees["titre"], "resume": donnees.get("resume", ""),
            "source": donnees.get("source", "Saisie manuelle"), "lien": donnees["lien"],
            "langue": donnees.get("langue", "fr"), "date": jour, "fiche": donnees.get("fiche", "")}


# --- 2. Article de presse ------------------------------------------------------------------

def article_presse(articles: list[Article]) -> Article | None:
    """L'article de presse récent le plus récent dont le TITRE contient un mot-clé d'arnaque."""
    limite = datetime.now(timezone.utc) - timedelta(days=config.ARNAQUE_PRESSE_JOURS)
    for article in articles:  # déjà triés du plus récent au plus ancien
        if article.type_source == "presse" and article.date and article.date >= limite \
                and _compter(article.titre, config.MOTS_CLES_ARNAQUE):
            return article
    return None


def fiche_la_plus_proche(texte: str, fiches: list[dict]) -> dict:
    """La fiche dont le plus de mots-clés apparaissent dans le texte."""
    meilleure = max(fiches, key=lambda f: _compter(texte, f["mots_cles"]))
    if _compter(texte, meilleure["mots_cles"]) == 0:
        return _fiche_par_id(fiches, FICHE_PAR_DEFAUT) or fiches[0]
    return meilleure


def _compter(texte: str, mots_cles: list[str]) -> int:
    """Nombre de mots-clés différents trouvés en début de mot (« arnaque » trouve « arnaques »)."""
    return sum(re.search(r"\b" + re.escape(mot), texte, re.IGNORECASE) is not None for mot in mots_cles)


# --- 3. Bibliothèque -------------------------------------------------------------------------

def charger_fiches() -> list[dict]:
    """Fiches valides de bibliotheques/arnaques/, triées par identifiant (ordre de rotation stable)."""
    fiches = []
    for chemin in sorted(config.DOSSIER_ARNAQUES.glob("*.json")):
        try:
            fiche = json.loads(chemin.read_text(encoding="utf-8"))
        except json.JSONDecodeError as erreur:
            log.warning("[Arnaques] fiche %s illisible (%s) : ignorée", chemin.name, erreur)
            continue
        manquants = [c for c in CHAMPS_FICHE if not fiche.get(c)]
        if manquants:
            log.warning("[Arnaques] fiche %s incomplète (%s) : ignorée", chemin.name, ", ".join(manquants))
            continue
        fiches.append(fiche)
    if not fiches:
        log.error("[Arnaques] aucune fiche valide dans %s : fiche de secours", config.DOSSIER_ARNAQUES)
        return [FICHE_SECOURS]
    return fiches


def _fiche_par_id(fiches: list[dict], identifiant: str) -> dict | None:
    return next((f for f in fiches if f["id"] == identifiant), None)
