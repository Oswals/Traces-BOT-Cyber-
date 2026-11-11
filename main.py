"""
TRACES : lance le pipeline complet.

Collecte -> enrichissement (CVE, NVD, KEV) -> sélection -> assemblage -> HTML.

Utilisation :
    python main.py            -> numéro du jour dans sortie/traces_AAAA-MM-JJ.html
    python main.py --details  -> affiche aussi le résumé de la collecte et des failles
    python main.py --demo     -> numéro de démonstration (données fictives, sans Internet)
    python main.py --debug    -> messages détaillés pour déboguer
    python main.py --planning 7 -> rubrique Histoire des 7 prochains jours (n'écrit rien)
    python main.py --sans-pdf -> seulement le HTML (plus rapide)

Chaque matin, le Planificateur de tâches Windows lance outils/lancer_traces.ps1, qui exécute
ce fichier et écrit data/journal.log (installation : outils/installer_tache.ps1).
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
from mise_en_page.pdf import exporter_pdf
from selection import selectionner

JOURS = ["lundi", "mardi", "mercredi", "jeudi", "vendredi", "samedi", "dimanche"]
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


def afficher_planning(nb_jours: int) -> None:
    """Événements Histoire prévus, sans rien enregistrer dans publies.json."""
    from histoire.choix import planning

    print(f"\n=== L'histoire : les {nb_jours} prochains jours ===\n")
    for jour, choix in planning(date.today(), nb_jours):
        entete = f"{JOURS[jour.weekday()]:9} {jour:%d/%m}"
        if not choix:
            print(f"{entete}  aucun candidat (lance python -m histoire.catalogue)")
            continue
        c = choix["candidat"]
        print(f"{entete}  {c['envergure']:5} {choix['type']:10} {c['categorie']:16} {c['titre'][:55]}")
        details = f"{c['date']} · {c.get('source', 'Bibliothèque')}"
        if choix["anniversaire"]:
            details += f" · Il y a {jour.year - int(c['date'][:4])} ans, jour pour jour"
        print(f"{'':16}  {details}")


def main() -> None:
    parser = argparse.ArgumentParser(description="TRACES, magazine de veille cyber")
    parser.add_argument("--demo", action="store_true", help="numéro de démonstration (données fictives)")
    parser.add_argument("--details", action="store_true", help="affiche le résumé de la collecte")
    parser.add_argument("--debug", action="store_true", help="logs détaillés")
    parser.add_argument("--planning", type=int, metavar="N", help="rubrique Histoire des N prochains jours")
    parser.add_argument("--sans-pdf", action="store_true", help="ne produit que le HTML")
    args = parser.parse_args()
    sys.stdout.reconfigure(encoding="utf-8")  # accents corrects dans la console Windows

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(levelname)s: %(message)s")

    preparer_dossiers()
    if args.planning:
        afficher_planning(args.planning)
        return
    if args.demo:
        from mise_en_page.exemple import NUMERO
        chemin = generer_html(NUMERO, config.DOSSIER_SORTIE / "traces_demo.html")
        print(f"Numéro de démonstration généré : {chemin}")
        if not args.sans_pdf:
            print(f"PDF : {exporter_pdf(chemin) or 'non produit (voir les erreurs ci-dessus)'}")
        return

    articles = collecter_tout()
    failles = enrichir(articles)
    if args.details:
        afficher_resume(articles)
        afficher_failles(failles)

    # Le numéro est connu avant la sélection : il sert à faire tourner la « fiche du numéro »
    aujourd_hui = date.today()
    numero_jour = numero_du_jour(aujourd_hui)
    try:
        selection = selectionner(articles, failles, numero_jour)
    except ValueError as erreur:
        logging.error("%s", erreur)
        sys.exit(1)

    # L'histoire du jour : choisie maintenant, inscrite dans publies.json seulement si le numéro est généré
    from histoire import choix as choix_histoire
    from histoire.mise_en_forme import preparer
    histoire = choix_histoire.histoire_du_jour(aujourd_hui)

    numero = assembler(selection, articles, failles, numero_jour, aujourd_hui,
                       histoire=preparer(histoire, aujourd_hui))
    chemin = generer_html(numero, config.DOSSIER_SORTIE / f"traces_{aujourd_hui.isoformat()}.html")
    choix_histoire.memoriser(aujourd_hui, histoire)
    pdf = None if args.sans_pdf else exporter_pdf(chemin)
    print(f"\nTRACES N°{numero['numero']:02d} généré : {chemin}")
    if not args.sans_pdf:
        print(f"PDF : {pdf or 'non produit (voir les erreurs ci-dessus)'}")
    print(f"À la une : {numero['une']['titre']}")
    if histoire:
        print(f"L'histoire : {histoire['candidat']['titre']} ({histoire['type']})")


if __name__ == "__main__":
    main()
