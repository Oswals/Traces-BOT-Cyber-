"""
Sous-étape 7a : EXPLORATION des sources de la rubrique « L'histoire ».

Ce script ne modifie rien dans le magazine. Il teste chaque source déclarée dans
config.py, compte les événements qu'elle apporterait (depuis 2005), les classe par
catégorie et par envergure, et affiche le résultat pour validation.

Lancement :  python -m histoire.explorer
Résultat détaillé :  data/exploration_histoire.json
"""

import json
import logging
import sys
from collections import Counter
from datetime import date

import config

from . import attack, kev_ancien, wikimedia

log = logging.getLogger("explorer")


def explorer_wikipedia(aujourd_hui: date) -> tuple[list[dict], list[dict]]:
    """Renvoie (bilan par source, événements retenus après dédoublonnage)."""
    bilans, trouves = [], {}   # trouves : {qid: {"sources": [...], "categories": [...]}}
    for source in config.HISTOIRE_SOURCES_WIKIPEDIA:
        nom = f"{source['wiki']}:{source['titre']}"
        log.info("Source %s", nom)
        if not wikimedia.page_existe(source["wiki"], source["titre"]):
            bilans.append({"source": nom, "categorie": source["categorie"], "existe": False})
            continue
        if source["type"] == "liste":
            pages = wikimedia.liens_de_page(source["wiki"], source["titre"])
        else:
            pages = wikimedia.membres_categorie(source["wiki"], source["titre"], source.get("profondeur", 0))
        for titre, qid in pages.items():
            entree = trouves.setdefault(qid, {"sources": [], "categories": [], "titre_source": titre})
            entree["sources"].append(nom)
            entree["categories"].append(source["categorie"])
        bilans.append({"source": nom, "categorie": source["categorie"], "existe": True,
                       "articles": len(pages), "qids": list(pages.values())})

    log.info("Wikidata : dates et langues de %d articles...", len(trouves))
    infos = wikimedia.entites(list(trouves))

    # On ne garde que les événements datés entre 2005 et aujourd'hui, hors exclusions
    exclus = set(config.HISTOIRE_EXCLURE)
    evenements = []
    for qid, entree in trouves.items():
        info = infos.get(qid)
        if not info or not info["date"]:
            continue
        if not config.HISTOIRE_ANNEE_MIN <= int(info["date"][:4]) <= aujourd_hui.year \
                or info["date"] > aujourd_hui.isoformat():
            continue
        titre = info["titre_en"] or info["titre_fr"] or entree["titre_source"]
        if titre in exclus:
            continue
        categorie = config.HISTOIRE_CATEGORIE_FORCEE.get(titre) or min(
            entree["categories"], key=config.HISTOIRE_PRIORITE_CATEGORIES.index)
        evenements.append({"qid": qid, "titre": titre, **info, "categorie": categorie,
                           "conflit": len(set(entree["categories"])) > 1, "sources": entree["sources"]})

    dates = {e["qid"] for e in evenements}
    for bilan in bilans:
        if bilan.get("existe"):
            bilan["dates_depuis_2005"] = sum(1 for q in set(bilan.pop("qids")) if q in dates)

    # Envergure : langues d'abord ; on ne mesure les vues que si les langues ne suffisent pas
    a_mesurer = [e for e in evenements if e["langues"] < config.HISTOIRE_SEUIL_LANGUES]
    log.info("Vues sur 12 mois de %d pages (1 requête par seconde, mises en cache)...", len(a_mesurer))
    vues_en = wikimedia.vues_annuelles("en", [e["titre_en"] for e in a_mesurer if e["titre_en"]], aujourd_hui)
    vues_fr = wikimedia.vues_annuelles("fr", [e["titre_fr"] for e in a_mesurer if not e["titre_en"]], aujourd_hui)
    for e in evenements:
        e["vues"] = vues_en.get(e["titre_en"]) if e["titre_en"] else vues_fr.get(e["titre_fr"])
        e["envergure"] = envergure(e)
    return bilans, evenements


def envergure(e: dict) -> str:
    """« grand », « moyen » ou « écarté » (page trop confidentielle)."""
    if e["titre"] in config.HISTOIRE_FORCER_GRAND:
        return "grand"
    if e["titre"] in config.HISTOIRE_FORCER_MOYEN:
        return "moyen"
    if e["langues"] >= config.HISTOIRE_SEUIL_LANGUES or (e["vues"] or 0) >= config.HISTOIRE_SEUIL_VUES:
        return "grand"
    if (e["vues"] or 0) < config.HISTOIRE_VUES_MIN:
        return "écarté"
    return "moyen"


# --- Affichage ---------------------------------------------------------------------

def afficher_wikipedia(bilans: list[dict], evenements: list[dict]) -> None:
    print("\n=== 1. WIKIPÉDIA : sources testées ===\n")
    print(f"{'source':58} {'catégorie':17} {'articles':>8} {'datés≥2005':>10}")
    for b in bilans:
        if not b["existe"]:
            print(f"{b['source'][:58]:58} {b['categorie']:17} {'INTROUVABLE':>19}")
        else:
            print(f"{b['source'][:58]:58} {b['categorie']:17} {b['articles']:8} {b['dates_depuis_2005']:10}")

    print(f"\nAprès dédoublonnage : {len(evenements)} événements datés depuis {config.HISTOIRE_ANNEE_MIN}"
          f" ({sum(e['conflit'] for e in evenements)} trouvés dans des sources de catégories différentes).")
    print(f"Date au jour près (utile pour les anniversaires) : "
          f"{sum(e['precision'] == 11 for e in evenements)}")

    trouves = {e["titre"] for e in evenements}
    absents = [t for t in config.HISTOIRE_FORCER_GRAND if t not in trouves]
    if absents:
        print("Forcés en « grand » mais absents des sources :", ", ".join(absents))

    for categorie in config.HISTOIRE_CATEGORIES:
        for env in ("grand", "moyen"):
            liste = sorted((e for e in evenements if e["categorie"] == categorie and e["envergure"] == env),
                           key=lambda e: (-e["langues"], -(e["vues"] or 0)))
            print(f"\n-- {categorie} / {env} : {len(liste)}")
            for e in liste[:8]:
                vues = f"{e['vues']:,}".replace(",", " ") if e["vues"] is not None else "–"
                print(f"   {e['date']}  {e['titre'][:60]:60} {e['langues']:3} langues  {vues:>9} vues")


def afficher_attack(liste: list[dict]) -> list[dict]:
    print("\n=== 2. MITRE ATT&CK : campagnes ===\n")
    if not liste:
        print("Données ATT&CK indisponibles.")
        return []
    retenues = [c for c in liste if c["date"] and c["date"][:4] >= str(config.HISTOIRE_ANNEE_MIN)
                and c["techniques"]]
    print(f"Campagnes actives : {len(liste)}, datées depuis {config.HISTOIRE_ANNEE_MIN} avec au moins "
          f"une technique : {len(retenues)}")
    if retenues:
        nb = sorted(len(c["techniques"]) for c in retenues)
        print(f"Techniques par campagne : de {nb[0]} à {nb[-1]} (médiane {nb[len(nb) // 2]})")
    for c in sorted(retenues, key=lambda c: c["date"], reverse=True)[:6]:
        print(f"   {c['date']}  {c['id']:6} {c['titre'][:55]:55} {len(c['techniques']):3} techniques")
    return retenues


def afficher_kev(liste: list[dict]) -> list[dict]:
    print("\n=== 3. CISA KEV : anciennes failles ===\n")
    rancon = [f for f in liste if f["rancongiciel"]]
    print(f"CVE d'au moins {config.KEV_AGE_MIN_ANS} ans dans le catalogue : {len(liste)}, "
          f"dont {len(rancon)} utilisées par des rançongiciels.")
    print(f"En 7b, la NVD dira lesquelles ont un CVSS >= {config.KEV_SCORE_MIN} ; "
          f"on en gardera {config.KEV_MAX_CANDIDATS} au maximum.")
    for f in rancon[:6]:
        print(f"   {f['cve']:16} {f['titre'][:70]}")
    return liste


def afficher_bilan(evenements: list[dict], campagnes: list[dict], kev: list[dict]) -> None:
    print("\n=== 4. BILAN : candidats par catégorie et par envergure ===\n")
    compte = Counter((e["categorie"], e["envergure"]) for e in evenements)
    print(f"{'catégorie':18} {'grand':>6} {'moyen (Wiki)':>13} {'+ ATT&CK':>9} {'+ KEV (max)':>12} {'écartés':>8}")
    for c in config.HISTOIRE_CATEGORIES:
        attaque = c == "CYBERATTAQUE"
        print(f"{c:18} {compte[(c, 'grand')]:6} {compte[(c, 'moyen')]:13} "
              f"{len(campagnes) if attaque else 0:9} "
              f"{min(len(kev), config.KEV_MAX_CANDIDATS) if attaque else 0:12} {compte[(c, 'écarté')]:8}")


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")  # accents corrects dans la console Windows
    sys.stderr.reconfigure(encoding="utf-8")
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    aujourd_hui = date.today()

    bilans, evenements = [], []
    try:
        bilans, evenements = explorer_wikipedia(aujourd_hui)
    except wikimedia.ContactManquant as erreur:
        print(f"\n[Wikipédia ignoré] {erreur}")
    campagnes = attack.campagnes()
    kev = kev_ancien.anciennes_failles(aujourd_hui)

    if bilans:
        afficher_wikipedia(bilans, evenements)
    campagnes = afficher_attack(campagnes)
    kev = afficher_kev(kev)
    afficher_bilan(evenements, campagnes, kev)

    config.DOSSIER_DATA.mkdir(exist_ok=True)
    fichier = config.DOSSIER_DATA / "exploration_histoire.json"
    fichier.write_text(json.dumps({"date": aujourd_hui.isoformat(), "sources": bilans, "wikipedia": evenements,
                                   "attack": campagnes, "kev": kev}, ensure_ascii=False, indent=1),
                       encoding="utf-8")
    print(f"\nDétail complet : {fichier}")


if __name__ == "__main__":
    main()
