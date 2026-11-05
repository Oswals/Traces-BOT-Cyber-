"""
TRACES : lance le pipeline complet.

Collecte -> enrichissement (CVE, NVD, KEV) -> sélection -> assemblage -> HTML.

Utilisation :
    python main.py            -> numéro du jour dans sortie/traces_AAAA-MM-JJ.html
    python main.py --details  -> affiche aussi le résumé de la collecte et des failles
    python main.py --demo     -> numéro de démonstration (données fictives, sans Internet)
    python main.py --debug    -> messages détaillés pour déboguer
"""

import argparse
import logging
import sys
from collections import defaultdict
from datetime import date

import config
from collecteurs import collecter_tout
from enrichissement import enrichir
from mise_en_page import assembler, generer_html, numero_du_jour
from selection import selectionner

EXEMPLES_PAR_SOURCE = 3  # nombre de titres affichés par source
FAILLES_AFFICHEES = 10   # nombre de failles affichées dans le résumé


def preparer_dossiers() -> None:
    # Dossiers créés automatiquement (ils sont ignorés par Git)
    for dossier in (config.DOSSIER_DATA, config.DOSSIER_SORTIE):
        dossier.mkdir(exist_ok=True)
    if not config.NVD_API_KEY:
        logging.warning("Clé NVD absente : copie .env.example en .env et remplis-la")


def afficher_resume(articles: list) -> None:
    par_source = defaultdict(list)
    for article in articles:
        par_source[article.source].append(article)

    for source, liste in par_source.items():
        print(f"\n=== {source} ({len(liste)} articles, type {liste[0].type_source}) ===")
        for article in liste[:EXEMPLES_PAR_SOURCE]:
            date = article.date.strftime("%d/%m/%Y") if article.date else "date ?"
            print(f"  [{date}] [{article.langue.upper()}] {article.titre}")
            if article.cves:
                print(f"      CVE : {', '.join(article.cves)}")
            print(f"      {article.lien}")

    print(f"\nTotal : {len(articles)} articles de {len(par_source)} sources.")


def afficher_failles(failles: list) -> None:
    exploitees = sum(f.exploitee for f in failles)
    critiques = sum((f.score or 0) >= 9 for f in failles)
    croisees = sum(len(f.sources) >= 2 for f in failles)
    print(f"\n=== Failles : {len(failles)} CVE, {exploitees} exploitées, "
          f"{critiques} critiques, {croisees} citées par plusieurs sources ===")

    for faille in failles[:FAILLES_AFFICHEES]:
        if faille.nvd and faille.score is not None:
            gravite = f"{faille.score:>4} {faille.nvd.gravite:<8}"
        else:
            gravite = "   ? non évaluée"
        exploitee = "EXPLOITÉE" if faille.exploitee else "         "
        print(f"  [{gravite}] {exploitee} {faille.cve}")
        if faille.nvd:
            produits = ", ".join(faille.nvd.produits[:3]) or "produit non précisé"
            if len(faille.nvd.produits) > 3:
                produits += f" et {len(faille.nvd.produits) - 3} autres"
            cwes = ", ".join(faille.nvd.cwes) or "CWE non précisée"
            print(f"      {produits} | {cwes} | CVSS {faille.nvd.version_cvss}")
        print(f"      Sources : {', '.join(faille.sources)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="TRACES, magazine de veille cyber")
    parser.add_argument("--demo", action="store_true", help="numéro de démonstration (données fictives)")
    parser.add_argument("--details", action="store_true", help="affiche le résumé de la collecte")
    parser.add_argument("--debug", action="store_true", help="logs détaillés")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(levelname)s: %(message)s")

    preparer_dossiers()
    if args.demo:
        from mise_en_page.exemple import NUMERO
        chemin = generer_html(NUMERO, config.DOSSIER_SORTIE / "traces_demo.html")
        print(f"Numéro de démonstration généré : {chemin}")
        return

    articles = collecter_tout()
    failles = enrichir(articles)
    if args.details:
        afficher_resume(articles)
        afficher_failles(failles)

    try:
        selection = selectionner(articles, failles)
    except ValueError as erreur:
        logging.error("%s", erreur)
        sys.exit(1)

    aujourd_hui = date.today()
    numero = assembler(selection, articles, failles, numero_du_jour(aujourd_hui), aujourd_hui)
    chemin = generer_html(numero, config.DOSSIER_SORTIE / f"traces_{aujourd_hui.isoformat()}.html")
    print(f"\nTRACES N°{numero['numero']:02d} généré : {chemin}")
    print(f"À la une : {numero['une']['titre']}")


if __name__ == "__main__":
    main()
