"""
Accès à Wikipédia, Wikidata et aux statistiques de vues de Wikimedia.

On suit les règles officielles de Wikimedia pour les robots d'API :
- un User-Agent qui dit qui on est ET comment nous contacter (TRACES_CONTACT dans .env) ;
- une requête à la fois, avec une pause entre deux ;
- le paramètre maxlag=5 : si les serveurs sont chargés, l'API nous demande d'attendre.

API REST : un service web qu'on interroge par une simple adresse (avec des paramètres)
et qui répond en JSON au lieu d'une page HTML. C'est fait pour les programmes.
"""

import json
import logging
from datetime import date, timedelta
from urllib.parse import quote, urlencode

import config
from collecteurs.reseau import telecharger

log = logging.getLogger(__name__)

WIKIDATA_API = "https://www.wikidata.org/w/api.php"
VUES_API = "https://wikimedia.org/api/rest_v1/metrics/pageviews/per-article"

# Propriétés Wikidata qui donnent la date d'un événement, par ordre de préférence
# (P585 = date, P580 = date de début, P575 = date de découverte, P577 = date de publication)
PROPRIETES_DATE = ["P585", "P580", "P575", "P577"]
PROPRIETE_NATURE = "P31"   # « nature de l'élément » : cyberattaque, fuite de données, film...
PROPRIETE_CVE = "P3587"    # identifiant CVE
# Sites Wikimedia qui ne sont pas des Wikipédia de langue (ne comptent pas dans les langues)
SITES_NON_LANGUES = {"commonswiki", "wikidatawiki", "specieswiki", "metawiki", "mediawikiwiki",
                     "sourceswiki", "wikimaniawiki", "outreachwiki", "simplewiki"}


class ContactManquant(Exception):
    """TRACES_CONTACT est vide : on n'a pas le droit d'interroger Wikimedia."""


def user_agent() -> str:
    """User-Agent au format demandé par Wikimedia : nom/version (contact) bibliothèque."""
    if not config.TRACES_CONTACT:
        raise ContactManquant(
            "TRACES_CONTACT est vide dans .env. Wikimedia exige une adresse de contact "
            "dans le User-Agent des robots : ajoute une ligne TRACES_CONTACT=... (voir .env.example).")
    return f"TRACES-veille-etudiant/3.0 (projet pedagogique; {config.TRACES_CONTACT}) python-requests"


def _get_json(url: str) -> dict | None:
    contenu = telecharger(url, entetes={"User-Agent": user_agent()}, delai=config.WIKIMEDIA_DELAI)
    if contenu is None:
        return None
    try:
        return json.loads(contenu)
    except json.JSONDecodeError:
        log.error("Réponse non JSON de %s (serveur surchargé ?)", url[:80])
        return None


def _api(site: str, parametres: dict):
    """Interroge l'API MediaWiki d'un site, et suit la « continuation » (résultats par pages).

    Renvoie chaque morceau de réponse l'un après l'autre (c'est un générateur : `yield`).
    """
    parametres = {**parametres, "format": "json", "formatversion": 2, "maxlag": 5}
    suite: dict = {}
    while True:
        reponse = _get_json(f"{site}?{urlencode({**parametres, **suite})}")
        if reponse is None:
            return
        if "error" in reponse:
            log.error("API %s : %s", site, reponse["error"].get("info", reponse["error"]))
            return
        yield reponse
        if "continue" not in reponse:
            return
        suite = reponse["continue"]


def api_wiki(langue: str) -> str:
    return f"https://{langue}.wikipedia.org/w/api.php"


def page_existe(langue: str, titre: str) -> bool:
    for morceau in _api(api_wiki(langue), {"action": "query", "titles": titre}):
        pages = morceau.get("query", {}).get("pages", [])
        return bool(pages) and not pages[0].get("missing") and not pages[0].get("invalid")
    return False


def _pages_avec_qid(morceau: dict) -> dict[str, str]:
    """{titre: identifiant Wikidata} des pages d'un morceau de réponse."""
    return {p["title"]: p["pageprops"]["wikibase_item"]
            for p in morceau.get("query", {}).get("pages", [])
            if p.get("ns") == 0 and "wikibase_item" in p.get("pageprops", {})}


def liens_de_page(langue: str, titre: str) -> dict[str, str]:
    """Articles liés depuis une page (ex. une liste), avec leur identifiant Wikidata."""
    resultat: dict[str, str] = {}
    for morceau in _api(api_wiki(langue), {
            "action": "query", "generator": "links", "titles": titre, "redirects": 1,
            "gplnamespace": 0, "gpllimit": "max", "prop": "pageprops", "ppprop": "wikibase_item"}):
        resultat.update(_pages_avec_qid(morceau))
    return resultat


def membres_categorie(langue: str, titre: str, profondeur: int = 0) -> dict[str, str]:
    """Articles d'une catégorie (et de ses sous-catégories jusqu'à `profondeur`)."""
    resultat: dict[str, str] = {}
    a_visiter, vues = [(titre, 0)], set()
    while a_visiter:
        categorie, niveau = a_visiter.pop(0)
        if categorie in vues:
            continue
        vues.add(categorie)
        for morceau in _api(api_wiki(langue), {
                "action": "query", "generator": "categorymembers", "gcmtitle": categorie,
                "gcmnamespace": "0|14", "gcmlimit": "max", "prop": "pageprops", "ppprop": "wikibase_item"}):
            resultat.update(_pages_avec_qid(morceau))
            if niveau < profondeur:
                a_visiter += [(p["title"], niveau + 1)
                              for p in morceau.get("query", {}).get("pages", []) if p.get("ns") == 14]
    return resultat


def _date_wikidata(claims: dict) -> tuple[str, int] | None:
    """(date AAAA-MM-JJ, précision) de l'événement, ou None.

    Précision Wikidata : 11 = au jour près, 10 = au mois, 9 = à l'année.
    """
    for propriete in PROPRIETES_DATE:
        for claim in claims.get(propriete, []):
            valeur = claim.get("mainsnak", {}).get("datavalue", {}).get("value", {})
            temps = valeur.get("time", "")  # ex. "+2017-05-12T00:00:00Z"
            if temps.startswith("+") and len(temps) >= 11:
                return temps[1:11].replace("-00", "-01"), valeur.get("precision", 9)
    return None


def entites(qids: list[str]) -> dict[str, dict]:
    """Infos Wikidata utiles, 50 identifiants par requête.

    Renvoie {qid: {date, precision, langues, titre_en, titre_fr, label_fr, label_en}}.
    """
    infos: dict[str, dict] = {}
    for i in range(0, len(qids), 50):
        for morceau in _api(WIKIDATA_API, {"action": "wbgetentities", "ids": "|".join(qids[i:i + 50]),
                                           "props": "claims|sitelinks|labels", "languages": "fr|en"}):
            for qid, entite in morceau.get("entities", {}).items():
                if "missing" in entite:
                    continue
                liens = entite.get("sitelinks", {})
                claims = entite.get("claims", {})
                date_ev = _date_wikidata(claims)
                infos[qid] = {
                    "date": date_ev[0] if date_ev else None,
                    "precision": date_ev[1] if date_ev else None,
                    "langues": sum(1 for s in liens if s.endswith("wiki") and s not in SITES_NON_LANGUES),
                    "titre_en": liens.get("enwiki", {}).get("title"),
                    "titre_fr": liens.get("frwiki", {}).get("title"),
                    "label_fr": entite.get("labels", {}).get("fr", {}).get("value"),
                    "label_en": entite.get("labels", {}).get("en", {}).get("value"),
                    "natures": _valeurs(claims, PROPRIETE_NATURE, "id"),
                    "cves": sorted(set(_valeurs(claims, PROPRIETE_CVE))),
                }
    return infos


def _valeurs(claims: dict, propriete: str, cle: str | None = None) -> list[str]:
    """Valeurs d'une propriété Wikidata (cle="id" pour un lien vers un autre élément)."""
    valeurs = []
    for claim in claims.get(propriete, []):
        valeur = claim.get("mainsnak", {}).get("datavalue", {}).get("value")
        if cle and isinstance(valeur, dict):
            valeur = valeur.get(cle)
        if isinstance(valeur, str):
            valeurs.append(valeur)
    return valeurs


def qids_de_titres(langue: str, titres: list[str]) -> dict[str, str]:
    """{titre: identifiant Wikidata} de pages données par leur titre (ex. événements forcés)."""
    resultat: dict[str, str] = {}
    for i in range(0, len(titres), 50):
        for morceau in _api(api_wiki(langue), {"action": "query", "titles": "|".join(titres[i:i + 50]),
                                               "redirects": 1, "prop": "pageprops", "ppprop": "wikibase_item"}):
            resultat.update(_pages_avec_qid(morceau))
    return resultat


def lien_page(langue: str, titre: str) -> str:
    return f"https://{langue}.wikipedia.org/wiki/{quote(titre.replace(' ', '_'), safe='')}"


# --- Nombre de vues sur 12 mois, avec cache ---------------------------------------

def _lire_cache_vues() -> dict:
    try:
        return json.loads(config.FICHIER_CACHE_VUES.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _ecrire_cache_vues(cache: dict) -> None:
    config.DOSSIER_DATA.mkdir(exist_ok=True)
    config.FICHIER_CACHE_VUES.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")


def vues_annuelles(langue: str, titres: list[str], aujourd_hui: date | None = None) -> dict[str, int]:
    """Vues humaines (hors robots) des 12 derniers mois complets, pour chaque titre."""
    aujourd_hui = aujourd_hui or date.today()
    fin = aujourd_hui.replace(day=1) - timedelta(days=1)       # dernier jour du mois précédent
    debut = (fin.replace(day=1) - timedelta(days=334)).replace(day=1)  # 12 mois avant
    cache, limite = _lire_cache_vues(), (aujourd_hui - timedelta(days=config.VUES_CACHE_JOURS)).isoformat()
    resultat, nouveaux = {}, 0
    for titre in titres:
        cle = f"{langue}:{titre}"
        if cle in cache and cache[cle]["le"] >= limite:
            resultat[titre] = cache[cle]["vues"]
            continue
        url = (f"{VUES_API}/{langue}.wikipedia/all-access/user/{quote(titre.replace(' ', '_'), safe='')}"
               f"/monthly/{debut:%Y%m%d}00/{fin:%Y%m%d}00")
        reponse = _get_json(url)
        vues = sum(m.get("views", 0) for m in reponse.get("items", [])) if reponse else 0
        cache[cle] = {"vues": vues, "le": aujourd_hui.isoformat()}
        resultat[titre] = vues
        nouveaux += 1
        if nouveaux % 25 == 0:
            _ecrire_cache_vues(cache)  # on sauvegarde en route : une coupure ne fait pas tout perdre
            log.info("  ... %d pages mesurées", nouveaux)
    _ecrire_cache_vues(cache)
    return resultat
