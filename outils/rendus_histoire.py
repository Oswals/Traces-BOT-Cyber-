"""
Contrôle de la mise en page Histoire : génère un numéro par type de page (fiche technique
ATT&CK / CISA / Wikipédia, fiche découverte courte et longue, épisode non relu avec doutes)
et deux « pires cas » remplis au maximum. À mesurer ensuite avec outils/deborde.ps1.

Usage :  python outils/rendus_histoire.py          -> fichiers dans sortie/controle/
Nécessite le catalogue (bibliotheques/histoire/candidats.json) ; interroge Wikipédia et la NVD
pour les pages réelles (textes en cache ensuite).
"""

import copy
import json
import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config  # noqa: E402
from histoire import catalogue, extraits  # noqa: E402
from histoire import mise_en_forme as mf  # noqa: E402
from histoire.mise_en_forme import preparer  # noqa: E402
from mise_en_page import generer_html  # noqa: E402
from mise_en_page.exemple import NUMERO  # noqa: E402

SORTIE = config.DOSSIER_SORTIE / "controle"
JOUR = date(2026, 11, 9)
MOT = "Lorem ipsum dolor sit amet, consectetur adipiscing elit sed do. "


def par_titre(cands, t):
    return next(c for c in cands if t in (c.get("titre_en") or "") or t in c["titre"])


def rendre(nom, histoire):
    numero = copy.deepcopy(NUMERO)
    numero["histoire"] = histoire
    chemin = generer_html(numero, SORTIE / f"histoire_{nom}.html")
    print(f"{chemin.name:40} double={histoire['double']!s:5} rubriques={len(histoire['sections'])} "
          f"doutes={len(histoire['doutes'])}")


def main():
    SORTIE.mkdir(parents=True, exist_ok=True)
    cands = catalogue.lire().get("candidats", [])
    if not cands:
        sys.exit("Catalogue vide : lance d'abord python -m histoire.catalogue")

    attack = max((c for c in cands if c["source"] == "MITRE ATT&CK"), key=lambda c: len(c["techniques"]))
    kev = next(c for c in cands if c["source"] == "CISA KEV")
    cas = {
        "technique_attack": (attack, "technique"),
        "technique_kev": (kev, "technique"),
        "technique_wiki": (par_titre(cands, "Dirty COW"), "technique"),
        "decouverte_crowdstrike": (par_titre(cands, "CrowdStrike"), "découverte"),
        "decouverte_equifax": (par_titre(cands, "Equifax"), "découverte"),
        "decouverte_heartbleed": (par_titre(cands, "Heartbleed"), "découverte"),
    }
    for nom, (c, t) in cas.items():
        rendre(nom, preparer({"candidat": c, "type": t, "anniversaire": True}, JOUR))

    # Épisode NON relu : les doutes de l'auteur s'affichent en bas de page
    episode = json.loads((config.DOSSIER_EPISODES / "wannacry-2017.json").read_text(encoding="utf-8"))
    episode = {**episode, "verifie": False,
               "a_verifier": [(MOT * 4)[:mf.doutes.LONGUEUR_MAX]] * mf.doutes.NB_MAX}
    rendre("episode_non_relu", preparer({"candidat": episode, "type": "complet", "anniversaire": True}, JOUR))

    # Pires cas : chapeau, rubriques et doutes à la longueur maximale
    base = preparer({"candidat": par_titre(cands, "CrowdStrike"), "type": "découverte", "anniversaire": True}, JOUR)
    for double, longueur in ((True, mf.LONGUEUR_SECTION_DOUBLE), (False, mf.LONGUEUR_SECTION_SIMPLE)):
        h = dict(base, double=double,
                 chapeau={"texte": (MOT * 10)[:extraits.LONGUEUR_CHAPEAU], "langue": "fr"},
                 sections=[{"titre": "Rubrique", "intertitre": "Background and context", "langue": "fr",
                            "texte": (MOT * 20)[:longueur]} for _ in range(6 if double else 3)],
                 doutes=[(MOT * 4)[:mf.doutes.LONGUEUR_MAX]] * mf.doutes.NB_MAX,
                 video={"titre": "Titre de vidéo de démonstration assez long", "auteur": "Chaîne", "lien": "https://example.org/"})
        rendre("pire_" + ("double" if double else "simple"), h)


if __name__ == "__main__":
    main()
