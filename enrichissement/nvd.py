"""
NVD (NIST) comme dictionnaire : score CVSS, type de faille (CWE), produits
touchés et description officielle d'une CVE. Jamais une source d'articles.

Les réponses sont gardées dans data/cache_nvd.json pour ne pas redemander
chaque jour la même CVE (la NVD limite le nombre de requêtes).
"""

import json
import logging
from dataclasses import asdict
from datetime import datetime, timedelta, timezone

import config
from collecteurs.reseau import telecharger

from .faille import FicheNVD

log = logging.getLogger(__name__)

# Ordre de préférence des versions CVSS. La 3.x d'abord : c'est elle qui donne
# les 8 cases du « profil de la faille » (accès, difficulté, compte nécessaire...).
VERSIONS_CVSS = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")


def fiches_nvd(cves: list[str]) -> dict[str, FicheNVD | None]:
    """Fiche NVD de chaque CVE (None si la NVD ne la connaît pas)."""
    cache = _charger_cache()
    limite = datetime.now(timezone.utc) - timedelta(days=config.NVD_CACHE_JOURS)
    a_demander = [cve for cve in cves
                  if cve not in cache or datetime.fromisoformat(cache[cve]["date"]) < limite]

    if a_demander:
        delai = config.NVD_DELAI_AVEC_CLE if config.NVD_API_KEY else config.NVD_DELAI_SANS_CLE
        log.info("[NVD] %d CVE à demander, %d déjà en cache (environ %d s)",
                 len(a_demander), len(cves) - len(a_demander), len(a_demander) * delai)
        try:
            for cve in a_demander:
                reussi, fiche = _interroger(cve, delai)
                if not reussi:
                    log.warning("[NVD] injoignable : on s'arrête là et on garde le cache")
                    break
                cache[cve] = {"date": datetime.now(timezone.utc).isoformat(), "fiche": fiche}
        finally:
            # Même si on interrompt avec Ctrl+C, ce qui a été récupéré est gardé
            _sauver_cache(cache)

    fiches = {}
    for cve in cves:
        fiche = cache.get(cve, {}).get("fiche")
        fiches[cve] = FicheNVD(**fiche) if fiche else None
    return fiches


def _interroger(cve: str, delai: float) -> tuple[bool, dict | None]:
    """Renvoie (requête réussie ?, fiche ou None si la CVE est inconnue de la NVD)."""
    entetes = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
    contenu = telecharger(config.NVD_API_URL + cve, entetes=entetes, delai=delai)
    if contenu is None:
        return False, None
    try:
        resultats = json.loads(contenu).get("vulnerabilities", [])
    except json.JSONDecodeError:
        log.error("[NVD] réponse illisible pour %s", cve)
        return False, None

    if not resultats:
        log.debug("[NVD] %s inconnue de la NVD", cve)
        return True, None
    return True, asdict(_extraire_fiche(resultats[0]["cve"]))


def _extraire_fiche(donnees: dict) -> FicheNVD:
    # 1. CVSS : première version disponible dans l'ordre de préférence
    mesure, cvss = {}, {}
    for version in VERSIONS_CVSS:
        liste = donnees.get("metrics", {}).get(version)
        if liste:
            # "Primary" = évaluation de la NVD elle-même ; sinon celle de l'éditeur
            mesure = next((m for m in liste if m.get("type") == "Primary"), liste[0])
            cvss = mesure.get("cvssData", {})
            break

    # 2. CWE : on ignore les valeurs "NVD-CWE-Other" / "NVD-CWE-noinfo"
    cwes = sorted({d["value"]
                   for faiblesse in donnees.get("weaknesses", [])
                   for d in faiblesse.get("description", [])
                   if d.get("value", "").startswith("CWE-")})

    # 3. Produits touchés, sans doublon et dans l'ordre d'apparition
    produits = []
    for bloc in donnees.get("affected", []):
        for touche in bloc.get("affectedData", []):
            nom = _nom_produit(touche.get("vendor", ""), touche.get("product", ""))
            if nom and nom not in produits:
                produits.append(nom)

    description = next((d["value"] for d in donnees.get("descriptions", [])
                        if d.get("lang") == "en"), "")

    return FicheNVD(
        score=cvss.get("baseScore"),
        gravite=cvss.get("baseSeverity") or mesure.get("baseSeverity", ""),  # en v2, rangé à côté
        vecteur=cvss.get("vectorString", ""),
        version_cvss=cvss.get("version", ""),
        cwes=cwes,
        produits=produits,
        description=description,
    )


def _nom_produit(editeur: str, produit: str) -> str:
    """"Ivanti" + "Connect Secure" -> "Ivanti Connect Secure" ; "" si inconnu."""
    editeur = "" if editeur.lower() == "n/a" else editeur.strip()
    produit = "" if produit.lower() == "n/a" else produit.strip()
    if produit.lower().startswith(editeur.lower()):  # "Cisco" + "Cisco Secure Email"
        return produit
    return f"{editeur} {produit}".strip()


def _charger_cache() -> dict:
    if not config.FICHIER_CACHE_NVD.exists():
        return {}
    try:
        return json.loads(config.FICHIER_CACHE_NVD.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log.warning("%s est corrompu, on repart de zéro", config.FICHIER_CACHE_NVD.name)
        return {}


def _sauver_cache(cache: dict) -> None:
    config.FICHIER_CACHE_NVD.parent.mkdir(exist_ok=True)
    config.FICHIER_CACHE_NVD.write_text(json.dumps(cache, indent=1, ensure_ascii=False),
                                        encoding="utf-8")
