"""
Choix de l'événement du jour et mémoire des publications (bibliotheques/publies.json).

Règles, dans l'ordre :
1. Envergure : « grand » les jours de HISTOIRE_JOURS_GRANDS (lundi, jeudi), « moyen » sinon.
2. Jamais la même catégorie que la veille.
3. Priorité à un anniversaire du jour (« Il y a N ans, jour pour jour »).
4. Grand : un épisode complet validé ("verifie": true) jamais publié, sinon une fiche découverte.
   Moyen : un candidat moyen jamais publié (fiche technique).
5. Si tout a été publié : on reprend celui dont la dernière publication est la plus ancienne.

Le choix est déterministe (pas de hasard qui change à chaque lancement) : le planning
des 7 prochains jours affiché par `python main.py --planning 7` est donc celui qui sortira,
tant que le catalogue et les épisodes ne changent pas.
"""

import hashlib
import json
import logging
from datetime import date, timedelta

import config

from . import catalogue
from .outils import normaliser

log = logging.getLogger(__name__)


# --- Lecture des bibliothèques ------------------------------------------------------------

def charger_publies() -> list[dict]:
    try:
        return json.loads(config.FICHIER_PUBLIES.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []
    except (OSError, json.JSONDecodeError) as erreur:
        log.error("%s illisible (%s) : on fait comme si rien n'avait été publié", config.FICHIER_PUBLIES, erreur)
        return []


def enregistrer_publies(publies: list[dict]) -> None:
    config.FICHIER_PUBLIES.write_text(json.dumps(publies, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")


def charger_episodes(valides_seulement: bool = True) -> list[dict]:
    """Épisodes complets de la bibliothèque. Par défaut, SEULEMENT ceux marqués "verifie": true.

    Un brouillon (relu par personne) n'est donc jamais publié comme épisode complet.
    """
    episodes = []
    for fichier in sorted(config.DOSSIER_EPISODES.glob("*.json")):
        try:
            episode = json.loads(fichier.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as erreur:
            log.error("Épisode illisible, ignoré : %s (%s)", fichier.name, erreur)
            continue
        if not valides_seulement or episode.get("verifie") is True:
            episodes.append(episode)
    return episodes


# --- Le choix -------------------------------------------------------------------------------

def envergure_du_jour(jour: date) -> str:
    return "grand" if jour.weekday() in config.HISTOIRE_JOURS_GRANDS else "moyen"


def _deja_publie(candidat: dict, publies: list[dict]) -> bool:
    """Vérifie l'identifiant ET le titre normalisé (un même événement peut venir de 2 sources)."""
    titres = {normaliser(t) for t in (candidat.get("titre"), candidat.get("titre_en")) if t}
    return any(p["id"] == candidat["id"] or p["titre_normalise"] in titres for p in publies)


def _derniere_publication(candidat: dict, publies: list[dict]) -> str:
    dates = [p["date"] for p in publies if p["id"] == candidat["id"]]
    return max(dates) if dates else ""


def _anniversaire(candidat: dict, jour: date) -> bool:
    return (candidat.get("precision_date") == "jour" and candidat["date"][5:10] == jour.strftime("%m-%d")
            and int(candidat["date"][:4]) < jour.year)


def _tirage(jour: date, candidat: dict) -> str:
    """Ordre « au hasard » mais reproductible : il ne dépend que de la date et de l'identifiant."""
    return hashlib.sha256(f"{jour.isoformat()}|{candidat['id']}".encode()).hexdigest()


def _meilleur(candidats: list[dict], jour: date, publies: list[dict]) -> dict:
    """Départage : la catégorie publiée le moins récemment, puis la notoriété (grand) ou le tirage (moyen)."""
    derniere_categorie = {}
    for p in publies:
        derniere_categorie[p["categorie"]] = max(p["date"], derniere_categorie.get(p["categorie"], ""))

    def cle(c):
        if c["envergure"] == "grand":
            second = (-(c.get("langues") or 0), -(c.get("vues") or 0), c["id"])
        else:
            second = (_tirage(jour, c),)
        return (derniere_categorie.get(c["categorie"], ""), *second)
    return min(candidats, key=cle)


def choisir(jour: date, candidats: list[dict], episodes: list[dict], publies: list[dict]) -> dict | None:
    """L'événement du jour : {"candidat", "type", "anniversaire"} ou None si le catalogue est vide.

    type : « complet » (épisode validé), « découverte » (grand sans épisode) ou « technique » (moyen).
    """
    # Relancer le même jour redonne le même choix
    for p in publies:
        if p["date"] == jour.isoformat():
            trouve = next((e for e in episodes + candidats if e["id"] == p["id"]), None)
            if trouve:
                return {"candidat": trouve, "type": p["type"], "anniversaire": _anniversaire(trouve, jour)}

    envergure = envergure_du_jour(jour)
    veille = next((p["categorie"] for p in publies if p["date"] == (jour - timedelta(days=1)).isoformat()), None)
    ids_episodes = {e["id"] for e in episodes}

    if envergure == "grand":
        # Les épisodes complets d'abord, puis les grands candidats (en fiche découverte)
        pool = [{**e, "envergure": "grand"} for e in episodes] + \
               [c for c in candidats if c["envergure"] == "grand" and c["id"] not in ids_episodes]
    else:
        pool = [c for c in candidats if c["envergure"] == "moyen"]
    if not pool:
        return None

    # Règle « jamais la même catégorie que la veille » (abandonnée seulement si impossible)
    pool = [c for c in pool if c["categorie"] != veille] or pool
    neufs = [c for c in pool if not _deja_publie(c, publies)]

    choix = None
    anniversaires = [c for c in neufs if _anniversaire(c, jour)]
    if anniversaires:
        complets = [c for c in anniversaires if c["id"] in ids_episodes]
        choix = _meilleur(complets or anniversaires, jour, publies)
    elif envergure == "grand" and any(c["id"] in ids_episodes for c in neufs):
        choix = _meilleur([c for c in neufs if c["id"] in ids_episodes], jour, publies)
    elif neufs:
        choix = _meilleur(neufs, jour, publies)
    else:
        # Tout a été publié : le plus anciennement publié revient
        choix = min(pool, key=lambda c: (_derniere_publication(c, publies), c["id"]))

    if envergure == "moyen":
        type_ = "technique"
    else:
        type_ = "complet" if choix["id"] in ids_episodes else "découverte"
    return {"candidat": choix, "type": type_, "anniversaire": _anniversaire(choix, jour)}


def entree_publie(jour: date, choix: dict) -> dict:
    c = choix["candidat"]
    return {"id": c["id"], "titre_normalise": normaliser(c.get("titre_en") or c["titre"]),
            "date": jour.isoformat(), "categorie": c["categorie"], "envergure": c["envergure"],
            "type": choix["type"]}


def histoire_du_jour(jour: date, enregistrer: bool = True) -> dict | None:
    """Choisit l'événement du jour et l'inscrit dans publies.json (une seule fois par jour)."""
    candidats = catalogue.mettre_a_jour().get("candidats", [])
    publies = charger_publies()
    choix = choisir(jour, candidats, charger_episodes(), publies)
    if choix and enregistrer and not any(p["date"] == jour.isoformat() for p in publies):
        enregistrer_publies(publies + [entree_publie(jour, choix)])
    return choix


def planning(debut: date, nb_jours: int) -> list[tuple[date, dict | None]]:
    """Simule les nb_jours prochains choix SANS rien écrire dans publies.json."""
    candidats = catalogue.lire().get("candidats", [])
    episodes, publies = charger_episodes(), charger_publies()
    resultat = []
    for i in range(nb_jours):
        jour = debut + timedelta(days=i)
        choix = choisir(jour, candidats, episodes, publies)
        resultat.append((jour, choix))
        if choix and not any(p["date"] == jour.isoformat() for p in publies):
            publies = publies + [entree_publie(jour, choix)]  # copie : le fichier n'est pas touché
    return resultat
