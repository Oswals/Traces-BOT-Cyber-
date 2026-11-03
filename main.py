"""
TRACES : lance le pipeline complet.

Étape 1 : vérifie seulement que le projet est bien installé.
Les étapes suivantes (collecte, enrichissement, mise en page...) s'ajouteront ici.

Utilisation :
    python main.py
"""

import config


def verifier_installation() -> None:
    # Dossiers créés automatiquement (ils sont ignorés par Git)
    for dossier in (config.DOSSIER_DATA, config.DOSSIER_SORTIE):
        dossier.mkdir(exist_ok=True)

    print("TRACES : installation OK")
    print(f"  Racine du projet : {config.RACINE}")
    if config.NVD_API_KEY:
        print("  Clé NVD         : trouvée dans .env")
    else:
        print("  Clé NVD         : absente (copie .env.example en .env et remplis-la)")


def main() -> None:
    verifier_installation()


if __name__ == "__main__":
    main()
