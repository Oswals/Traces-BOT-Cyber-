"""
Catalogue des événements candidats : bibliotheques/histoire/candidats.json

Trois sources, une seule liste :
- Wikipédia (FR + EN) via Wikidata : grands et moyens événements ;
- MITRE ATT&CK : campagnes d'attaque (moyens, CYBERATTAQUE) ;
- CISA KEV + NVD : anciennes failles exploitées par des rançongiciels (moyens, CYBERATTAQUE).

Le catalogue est reconstruit au plus une fois par semaine. Si une source est injoignable,
on garde ses candidats de la version précédente : le magazine ne reste jamais sans histoire.

Lancement manuel (avec rapport) :  python -m histoire.catalogue [--forcer]
"""

import argparse
import json
import logging
import sys
from collections import Counter
from datetime import date, timedelta

import config
from enrichissement.nvd import fiches_nvd

from . import attack, kev_ancien, wikimedia
from .outils import normaliser

log = logging.getLogger(__name__)

PRECISIONS = {11: "jour", 10: "mois", 9: "année"}


# --- 1. Wikipédia --------------------------------------------------------------------

def candidats_wikipedia(aujourd_hui: date) -> tuple[list[dict], list[dict]]:
    """Renvoie (bilan par source, candidats). Lève ContactManquant sans TRACES_CONTACT."""
    wikimedia.user_agent()  # vérifie le contact AVANT toute requête
    bilans, trouves = [], {}  # trouves : {qid: catégories des sources où il apparaît}
    for source in config.HISTOIRE_SOURCES_WIKIPEDIA:
        nom = f"{source['wiki']}:{source['titre']}"
        log.info("Wikipédia : %s", nom)
        if not wikimedia.page_existe(source["wiki"], source["titre"]):
            bilans.append({"source": nom, "categorie": source["categorie"], "existe": False})
            continue
        if source["type"] == "liste":
            pages = wikimedia.liens_de_page(source["wiki"], source["titre"])
        else:
            pages = wikimedia.membres_categorie(source["wiki"], source["titre"], source.get("profondeur", 0))
        for qid in pages.values():
            trouves.setdefault(qid, []).append(source["categorie"])
        bilans.append({"source": nom, "categorie": source["categorie"], "existe": True,
                       "articles": len(pages), "qids": sorted(set(pages.values()))})

    # Les événements forcés sont ajoutés même s'ils ne sont dans aucune source
    forces = config.HISTOIRE_FORCER_GRAND + config.HISTOIRE_FORCER_MOYEN
    for qid in wikimedia.qids_de_titres("en", forces).values():
        trouves.setdefault(qid, [])

    log.info("Wikidata : nature, date et langues de %d pages...", len(trouves))
    infos = wikimedia.entites(sorted(trouves))

    candidats = []
    for qid, categories_sources in trouves.items():
        info = infos.get(qid)
        if info:
            candidat = _candidat_wikipedia(qid, info, categories_sources, aujourd_hui)
            if candidat:
                candidats.append(candidat)

    # Envergure : on ne mesure les vues que si le nombre de langues ne suffit pas
    a_mesurer = [c for c in candidats if c["langues"] < config.HISTOIRE_SEUIL_LANGUES]
    log.info("Vues sur 12 mois de %d pages (1 requête par seconde, en cache 30 jours)...", len(a_mesurer))
    vues_en = wikimedia.vues_annuelles("en", [c["titre_en"] for c in a_mesurer if c["titre_en"]], aujourd_hui)
    vues_fr = wikimedia.vues_annuelles("fr", [c["titre_fr"] for c in a_mesurer if not c["titre_en"]], aujourd_hui)
    for c in candidats:
        c["vues"] = vues_en.get(c["titre_en"]) if c["titre_en"] else vues_fr.get(c["titre_fr"])
        c["envergure"] = envergure(c)
    candidats = [c for c in candidats if c["envergure"] != "écarté"]

    gardes = {c["id"].removeprefix("wd-") for c in candidats}
    for bilan in bilans:
        if bilan.get("existe"):
            bilan["retenus"] = sum(1 for q in bilan.pop("qids") if q in gardes)
    return bilans, candidats


def _candidat_wikipedia(qid: str, info: dict, categories_sources: list[str], aujourd_hui: date) -> dict | None:
    """Un candidat, ou None s'il ne passe pas les filtres (date, nature, exclusions)."""
    titre_ref = info["titre_en"] or info["titre_fr"]
    if not titre_ref or titre_ref in config.HISTOIRE_EXCLURE or not info["date"]:
        return None
    if not config.HISTOIRE_ANNEE_MIN <= int(info["date"][:4]) or info["date"] > aujourd_hui.isoformat():
        return None

    force = titre_ref in config.HISTOIRE_FORCER_GRAND + config.HISTOIRE_FORCER_MOYEN
    natures = [n for n in info["natures"] if n in config.HISTOIRE_NATURES]
    if not natures and not force:
        return None  # pas un événement cyber (film, appli, élection...)

    # Catégorie : forcée, sinon la plus précise des natures, sinon celle des sources
    possibles = [config.HISTOIRE_NATURES[n] for n in natures if config.HISTOIRE_NATURES[n]] or categories_sources
    categorie = config.HISTOIRE_CATEGORIE_FORCEE.get(titre_ref) or (
        min(possibles, key=config.HISTOIRE_PRIORITE_CATEGORIES.index) if possibles else None)
    if not categorie:
        return None

    langue = "fr" if info["titre_fr"] else "en"
    return {
        "id": f"wd-{qid}",
        "titre": info["titre_fr"] or info["titre_en"],
        "titre_en": info["titre_en"],
        "titre_fr": info["titre_fr"],
        "date": info["date"],
        "precision_date": PRECISIONS.get(info["precision"], "année"),
        "categorie": categorie,
        "envergure": None,  # calculée après la mesure des vues
        "source": "Wikipédia",
        "langue": langue,
        "lien": wikimedia.lien_page(langue, info["titre_fr"] or info["titre_en"]),
        "lien_en": wikimedia.lien_page("en", info["titre_en"]) if info["titre_en"] else "",
        "licence": "CC BY-SA 4.0",
        "langues": info["langues"],
        "vues": None,
        "cves": info["cves"],
        "techniques": [],
        "resume": "",  # le texte de Wikipédia est lu au moment de la publication
    }


def envergure(c: dict) -> str:
    """« grand », « moyen » ou « écarté » (page trop confidentielle)."""
    titre = c.get("titre_en") or c.get("titre")
    if titre in config.HISTOIRE_FORCER_GRAND:
        return "grand"
    if titre in config.HISTOIRE_FORCER_MOYEN:
        return "moyen"
    if c["langues"] >= config.HISTOIRE_SEUIL_LANGUES or (c["vues"] or 0) >= config.HISTOIRE_SEUIL_VUES:
        return "grand"
    if (c["vues"] or 0) < config.HISTOIRE_VUES_MIN:
        return "écarté"
    return "moyen"


# --- 2. MITRE ATT&CK -------------------------------------------------------------------

def candidats_attack() -> list[dict]:
    resultat = []
    for c in attack.campagnes():
        if not c["date"] or int(c["date"][:4]) < config.HISTOIRE_ANNEE_MIN or not c["techniques"]:
            continue
        resultat.append({
            "id": f"attack-{c['id']}", "titre": c["titre"], "titre_en": c["titre"], "titre_fr": None,
            "date": c["date"], "precision_date": "mois",  # ATT&CK ne date qu'au mois près
            "categorie": "CYBERATTAQUE", "envergure": "moyen", "source": "MITRE ATT&CK",
            "langue": "en", "lien": c["lien"], "lien_en": c["lien"], "licence": "",
            "langues": None, "vues": None, "cves": [], "techniques": c["techniques"],
            "resume": c["resume"],
        })
    return resultat


# --- 3. Anciennes failles CISA KEV -------------------------------------------------------

def candidats_kev(aujourd_hui: date) -> list[dict]:
    """Failles d'au moins 2 ans exploitées par des rançongiciels, les plus graves d'abord."""
    failles = [f for f in kev_ancien.anciennes_failles(aujourd_hui) if f["rancongiciel"]]
    if not failles:
        return []
    fiches = fiches_nvd([f["cve"] for f in failles])
    resultat = []
    for f in failles:
        fiche = fiches.get(f["cve"])
        if not fiche or not fiche.publiee or fiche.score is None:
            continue  # sans date ni score, pas de fiche technique possible
        if int(fiche.publiee[:4]) < config.HISTOIRE_ANNEE_MIN:
            continue
        resultat.append({
            "id": f"kev-{f['cve']}", "titre": f["titre"], "titre_en": f["titre"], "titre_fr": None,
            "date": fiche.publiee, "precision_date": "jour",  # date de publication de la CVE
            "categorie": "CYBERATTAQUE", "envergure": "moyen", "source": "CISA KEV",
            "langue": "en", "lien": kev_ancien.LIEN_CATALOGUE + f["cve"], "lien_en": "",
            "licence": "", "langues": None, "vues": None, "cves": [f["cve"]], "techniques": [],
            "resume": f["resume"], "score": fiche.score, "vecteur": fiche.vecteur,
        })
    # CVSS >= 9 d'abord, puis par score décroissant
    resultat.sort(key=lambda c: (c["score"] < config.KEV_SCORE_MIN, -c["score"], c["date"]))
    return resultat[:config.KEV_MAX_CANDIDATS]


# --- Assemblage ---------------------------------------------------------------------------

def dedoublonner(wiki: list[dict], autres: list[dict]) -> list[dict]:
    """Wikipédia passe en premier ; un autre candidat qui partage une CVE ou un titre est retiré."""
    cves = {cve for c in wiki for cve in c["cves"]}
    titres = {normaliser(t) for c in wiki for t in (c["titre"], c["titre_en"]) if t}
    gardes = []
    for c in autres:
        if set(c["cves"]) & cves or normaliser(c["titre"]) in titres:
            continue
        gardes.append(c)
        cves |= set(c["cves"])
        titres.add(normaliser(c["titre"]))
    return wiki + gardes


def lire() -> dict:
    """Le catalogue actuel ({} s'il n'existe pas encore)."""
    try:
        return json.loads(config.FICHIER_CANDIDATS.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def mettre_a_jour(forcer: bool = False, aujourd_hui: date | None = None) -> dict:
    """Reconstruit le catalogue s'il a plus de CANDIDATS_MAJ_JOURS jours (ou si forcer)."""
    aujourd_hui = aujourd_hui or date.today()
    ancien = lire()
    limite = (aujourd_hui - timedelta(days=config.CANDIDATS_MAJ_JOURS)).isoformat()
    if ancien and not forcer and ancien.get("mis_a_jour", "") > limite:
        return ancien

    precedents = {}  # candidats de la version précédente, par source (secours)
    for c in ancien.get("candidats", []):
        precedents.setdefault(c["source"], []).append(c)

    bilans = ancien.get("sources_wikipedia", [])
    try:
        bilans, wiki = candidats_wikipedia(aujourd_hui)
    except wikimedia.ContactManquant as erreur:
        log.warning("%s", erreur)
        wiki = []
    wiki = wiki or precedents.get("Wikipédia", [])
    autres = (candidats_attack() or precedents.get("MITRE ATT&CK", [])) + \
             (candidats_kev(aujourd_hui) or precedents.get("CISA KEV", []))

    candidats = sorted(dedoublonner(wiki, autres), key=lambda c: (c["date"], c["id"]))
    catalogue = {"mis_a_jour": aujourd_hui.isoformat(), "sources_wikipedia": bilans, "candidats": candidats}
    config.FICHIER_CANDIDATS.parent.mkdir(parents=True, exist_ok=True)
    config.FICHIER_CANDIDATS.write_text(json.dumps(catalogue, ensure_ascii=False, indent=1) + "\n",
                                        encoding="utf-8")
    log.info("Catalogue enregistré : %d candidats", len(candidats))
    return catalogue


# --- Rapport ---------------------------------------------------------------------------------

def afficher(catalogue: dict) -> None:
    candidats = catalogue.get("candidats", [])
    print(f"\n=== Catalogue Histoire du {catalogue.get('mis_a_jour')} : {len(candidats)} candidats ===")

    print(f"\n{'source Wikipédia':58} {'catégorie':17} {'articles':>8} {'retenus':>8}")
    for b in catalogue.get("sources_wikipedia", []):
        if b["existe"]:
            print(f"{b['source'][:58]:58} {b['categorie']:17} {b['articles']:8} {b.get('retenus', 0):8}")
        else:
            print(f"{b['source'][:58]:58} {b['categorie']:17} {'INTROUVABLE':>17}")

    compte = Counter((c["categorie"], c["envergure"], c["source"]) for c in candidats)
    print(f"\n{'catégorie':18} {'grand':>6} {'moyen Wiki':>11} {'ATT&CK':>7} {'KEV':>5} {'total moyen':>12}")
    for cat in config.HISTOIRE_CATEGORIES:
        moyens = [compte[(cat, "moyen", s)] for s in ("Wikipédia", "MITRE ATT&CK", "CISA KEV")]
        print(f"{cat:18} {compte[(cat, 'grand', 'Wikipédia')]:6} {moyens[0]:11} {moyens[1]:7} {moyens[2]:5} "
              f"{sum(moyens):12}")
    jour = sum(c["precision_date"] == "jour" for c in candidats)
    print(f"\nDatés au jour près (utilisables pour les anniversaires) : {jour}/{len(candidats)}")

    for cat in config.HISTOIRE_CATEGORIES:
        for env in ("grand", "moyen"):
            liste = sorted((c for c in candidats if c["categorie"] == cat and c["envergure"] == env
                            and c["source"] == "Wikipédia"), key=lambda c: -(c["langues"] or 0))
            print(f"\n-- {cat} / {env} (Wikipédia) : {len(liste)}")
            for c in liste[:10]:
                vues = f"{c['vues']:,}".replace(",", " ") if c["vues"] is not None else "–"
                print(f"   {c['date']}  {c['titre'][:58]:58} {c['langues']:3} langues {vues:>9} vues")


def main() -> None:
    sys.stdout.reconfigure(encoding="utf-8")  # accents corrects dans la console Windows
    sys.stderr.reconfigure(encoding="utf-8")
    parametres = argparse.ArgumentParser(description="Catalogue des événements de la rubrique Histoire")
    parametres.add_argument("--forcer", action="store_true", help="reconstruire même s'il a moins d'une semaine")
    args = parametres.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    afficher(mettre_a_jour(forcer=args.forcer))


if __name__ == "__main__":
    main()
