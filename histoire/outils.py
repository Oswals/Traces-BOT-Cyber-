"""Petits outils communs à la rubrique Histoire."""

import re
import unicodedata


def normaliser(titre: str) -> str:
    """Titre comparable : minuscules, sans accents, sans ponctuation.

    « L'attaque WannaCry (2017) » -> « l attaque wannacry 2017 »
    """
    sans_accents = unicodedata.normalize("NFKD", titre).encode("ascii", "ignore").decode("ascii")
    return re.sub(r"[^a-z0-9]+", " ", sans_accents.lower()).strip()
