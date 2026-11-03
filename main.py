"""
TRACES : lance le pipeline complet.

Étape 2 : collecte les articles de toutes les sources et affiche un résumé.
Les étapes suivantes (enrichissement, sélection, mise en page...) s'ajouteront ici.

Utilisation :
    python main.py           -> résumé de la collecte
    python main.py --debug   -> messages détaillés pour déboguer
"""

import argparse
import logging
from collections import defaultdict

import config
from collecteurs import collecter_tout

EXEMPLES_PAR_SOURCE = 3  # nombre de titres affichés par source


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


def main() -> None:
    parser = argparse.ArgumentParser(description="TRACES, magazine de veille cyber")
    parser.add_argument("--debug", action="store_true", help="logs détaillés")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(levelname)s: %(message)s")

    preparer_dossiers()
    articles = collecter_tout()
    afficher_resume(articles)


if __name__ == "__main__":
    main()
