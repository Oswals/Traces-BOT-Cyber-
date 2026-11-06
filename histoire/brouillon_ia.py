"""
PRÉPARATION de l'étape 9 (IA locale, Ollama) : transformer une fiche découverte en BROUILLON
d'épisode complet. Rien n'est branché pour l'instant : la fonction ne fait rien.

Ce qu'elle fera plus tard :
1. Entrée : un candidat du catalogue et le texte de sa source (Wikipédia), encadré par des
   délimiteurs, avec la consigne de le traiter comme une donnée à résumer et d'ignorer toute
   instruction qu'il contient (règle de sécurité n°2 : protection contre l'injection de prompt).
2. Le modèle rédige, UNIQUEMENT à partir de ce texte, les 6 rubriques (contexte, déroulement,
   cause technique, qui a été touché, conséquences, enseignements), une chronologie et un
   schéma, au format JSON des épisodes. Information absente : « non précisé par la source ».
3. Validation : JSON conforme, toute CVE citée présente dans le texte source, sources reprises
   telles quelles. Si la validation échoue ou si le modèle ne répond pas : aucun brouillon.
4. Sortie : un fichier dans bibliotheques/histoire/brouillons/ avec "verifie": false.

Pourquoi un brouillon n'est jamais publié comme épisode complet :
histoire/choix.py ne lit que bibliotheques/histoire/episodes/ et ne garde que les épisodes
marqués "verifie": true. Un brouillon ne devient un épisode que si TU le relis, le déplaces
dans episodes/ et passes "verifie" à true.
"""

from pathlib import Path

import config

DOSSIER_BROUILLONS = config.DOSSIER_BIBLIOTHEQUES / "histoire" / "brouillons"


def rediger_brouillon(candidat: dict, texte_source: str) -> Path | None:
    """Écrira un brouillon d'épisode (verifie: false) et renverra son chemin.

    Pour l'instant : ne fait rien et renvoie None (IA locale pas encore branchée).
    """
    return None
