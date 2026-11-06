"""
Campagnes MITRE ATT&CK, lues dans les données officielles au format STIX.

STIX : format standard (JSON) pour échanger du renseignement sur les menaces. Chaque
objet a un type (« campaign », « attack-pattern » = technique…) et des objets
« relationship » relient les objets entre eux (ex. une campagne « uses » une technique).

Le fichier fait environ 55 Mo : on le garde dans data/ et on ne le retélécharge
qu'une fois par semaine au maximum.
"""

import json
import logging
import re
import time

import config
from collecteurs.reseau import telecharger

log = logging.getLogger(__name__)


def _fichier_stix() -> dict | None:
    """Le bundle STIX, depuis le cache s'il a moins de ATTACK_CACHE_JOURS jours."""
    fichier = config.FICHIER_CACHE_ATTACK
    age_max = config.ATTACK_CACHE_JOURS * 86400
    if not fichier.exists() or time.time() - fichier.stat().st_mtime > age_max:
        log.info("Téléchargement des données MITRE ATT&CK (environ 55 Mo)...")
        contenu = telecharger(config.ATTACK_URL)
        if contenu is not None:
            config.DOSSIER_DATA.mkdir(exist_ok=True)
            fichier.write_bytes(contenu)
        elif not fichier.exists():
            return None  # pas de réseau et pas de copie : tant pis pour cette source
        else:
            log.warning("ATT&CK injoignable : on garde l'ancienne copie")
    try:
        return json.loads(fichier.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as erreur:
        log.error("Fichier ATT&CK illisible (%s) : supprime %s pour le retélécharger", erreur, fichier)
        return None


def _reference_mitre(objet: dict) -> dict:
    """La référence officielle MITRE de l'objet : {external_id, url}."""
    for ref in objet.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref
    return {}


def nettoyer_description(texte: str) -> str:
    """Retire les marqueurs de citation « (Citation: ...) » et les liens markdown."""
    texte = re.sub(r"\(Citation:[^)]*\)", "", texte)
    texte = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", texte)  # [nom](lien) -> nom
    return re.sub(r"\s+", " ", texte).strip()


def campagnes() -> list[dict]:
    """Campagnes ATT&CK actives (ni révoquées, ni obsolètes), avec leurs techniques."""
    stix = _fichier_stix()
    if stix is None:
        return []
    objets = [o for o in stix.get("objects", [])
              if not o.get("revoked") and not o.get("x_mitre_deprecated")]
    par_id = {o["id"]: o for o in objets}

    # Techniques utilisées par chaque campagne
    techniques: dict[str, list[dict]] = {}
    for rel in objets:
        if rel.get("type") != "relationship" or rel.get("relationship_type") != "uses":
            continue
        source, cible = par_id.get(rel.get("source_ref")), par_id.get(rel.get("target_ref"))
        if source and cible and source["type"] == "campaign" and cible["type"] == "attack-pattern":
            ref = _reference_mitre(cible)
            techniques.setdefault(source["id"], []).append(
                {"id": ref.get("external_id", ""), "nom": cible.get("name", ""), "lien": ref.get("url", "")})

    resultat = []
    for c in objets:
        if c.get("type") != "campaign":
            continue
        ref = _reference_mitre(c)
        resultat.append({
            "id": ref.get("external_id", ""),
            "titre": c.get("name", ""),
            "date": (c.get("first_seen") or "")[:10] or None,
            "fin": (c.get("last_seen") or "")[:10] or None,
            "resume": nettoyer_description(c.get("description", "")),
            "lien": ref.get("url", ""),
            "techniques": sorted(techniques.get(c["id"], []), key=lambda t: t["id"]),
        })
    return resultat
