"""
Texte d'un article Wikipédia, rangé dans les 6 rubriques TRACES, pour les fiches découverte.

On demande à l'API le texte brut de l'article (extension TextExtracts), où chaque intertitre
apparaît sous la forme « == Titre == ». On reconnaît les intertitres par mots-clés
(« Background » -> Contexte, « Impact » -> Qui a été touché...). Une rubrique sans
intertitre correspondant reste vide : elle sera masquée, rien n'est inventé.

Le texte est une DONNÉE : il est raccourci, jamais interprété, et échappé par Jinja2.
Licence : CC BY-SA 4.0, attribution affichée sur la page avec le lien vers l'article.
"""

import json
import logging
import re
import time
from urllib.parse import unquote, urlparse

import config

from . import wikimedia
from .outils import normaliser

log = logging.getLogger(__name__)

FICHIER_CACHE = config.DOSSIER_DATA / "cache_extraits.json"
CACHE_JOURS = 30
LONGUEUR_CHAPEAU = 300

RUBRIQUES = [  # (clé, titre affiché, débuts de mots reconnus dans l'intertitre normalisé)
    ("contexte", "Contexte", ["background", "context", "contexte", "histor", "origin", "presentation"]),
    ("deroulement", "Déroulement", ["attack", "attaque", "timeline", "chronolog", "deroulement", "incident",
                                    "event", "evenement", "outage", "panne", "breach", "discover", "decouvert",
                                    "spread", "propagation"]),
    ("cause", "Cause technique", ["technical", "technique", "cause", "vulnerab", "faille", "mechanism",
                                  "fonctionnement", "description", "detail", "method", "exploit", "malware",
                                  "operation"]),
    ("touches", "Qui a été touché", ["impact", "affected", "victim", "target", "cible", "damage", "degat",
                                     "scope", "touche"]),
    ("consequences", "Conséquences", ["aftermath", "response", "reaction", "consequence", "suite",
                                      "investigation", "enquete", "legal", "lawsuit", "attribution", "arrest",
                                      "poursuite"]),
    ("enseignements", "Enseignements", ["lesson", "enseignement", "legacy", "heritage", "mitigation",
                                        "prevention", "remediation", "recommendation"]),
]
IGNORES = ["references", "see also", "voir aussi", "notes", "liens externes", "external links",
           "further reading", "bibliographie", "articles connexes", "sources"]
MOTIF_INTERTITRE = re.compile(r"^(={2,})\s*(.+?)\s*\1\s*$", re.MULTILINE)


def _lire_cache() -> dict:
    try:
        return json.loads(FICHIER_CACHE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def texte_article(lien: str) -> str | None:
    """Texte brut de l'article (avec ses intertitres), depuis le cache s'il a moins de 30 jours."""
    cache = _lire_cache()
    if lien in cache and time.time() - cache[lien]["le"] < CACHE_JOURS * 86400:
        return cache[lien]["texte"]

    adresse = urlparse(lien)
    langue = adresse.netloc.split(".")[0]
    titre = unquote(adresse.path.removeprefix("/wiki/")).replace("_", " ")
    texte = None
    try:
        for morceau in wikimedia._api(wikimedia.api_wiki(langue), {
                "action": "query", "prop": "extracts", "explaintext": 1, "exsectionformat": "wiki",
                "titles": titre, "redirects": 1}):
            pages = morceau.get("query", {}).get("pages", [])
            texte = pages[0].get("extract") if pages else None
            break
    except wikimedia.ContactManquant as erreur:
        log.warning("%s", erreur)
        return None
    if texte:
        cache[lien] = {"texte": texte, "le": time.time()}
        config.DOSSIER_DATA.mkdir(exist_ok=True)
        FICHIER_CACHE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
    return texte


def couper_phrases(texte: str, longueur: int) -> str:
    """Raccourcit à `longueur` caractères au plus, en s'arrêtant à la fin d'une phrase."""
    texte = re.sub(r"\s+", " ", texte).strip()
    if len(texte) <= longueur:
        return texte
    coupe = texte[:longueur]
    fin = max(coupe.rfind(". "), coupe.rfind(". "))
    return coupe[:fin + 1] if fin > longueur // 3 else coupe.rsplit(" ", 1)[0] + " […]"


def decouper(texte: str) -> tuple[str, list[tuple[str, str]]]:
    """(introduction, [(intertitre de niveau 2, texte de la partie, sous-parties comprises)])."""
    morceaux = MOTIF_INTERTITRE.split(texte)
    # split renvoie : [intro, "==", titre, texte, "===", titre, texte, ...]
    intro, parties = morceaux[0], []
    for i in range(1, len(morceaux) - 2, 3):
        niveau, titre, contenu = len(morceaux[i]), morceaux[i + 1], morceaux[i + 2]
        if niveau == 2 or not parties:
            parties.append([titre, contenu])
        else:
            parties[-1][1] += "\n" + contenu  # une sous-partie rejoint sa partie
    return intro.strip(), [(t, c.strip()) for t, c in parties]


def rubriques(texte: str, longueur: int) -> tuple[str, list[dict]]:
    """(chapeau, rubriques remplies) ; chaque intertitre ne sert qu'une fois."""
    intro, parties = decouper(texte)
    utilisees, resultat = set(), []
    for cle, titre_affiche, mots in RUBRIQUES:
        for i, (intertitre, contenu) in enumerate(parties):
            nom = normaliser(intertitre)
            if i in utilisees or not contenu or any(nom.startswith(x) for x in IGNORES):
                continue
            if any(re.search(rf"\b{m}", nom) for m in mots):
                utilisees.add(i)
                resultat.append({"cle": cle, "titre": titre_affiche, "intertitre": intertitre,
                                 "texte": couper_phrases(contenu, longueur)})
                break
    return couper_phrases(intro, LONGUEUR_CHAPEAU), resultat
