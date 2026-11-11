"""
Transforme un numéro (dictionnaire) en fichier HTML, avec les gabarits Jinja2.

Jinja2 remplit des gabarits HTML contenant des « trous » ({{ variable }}) et des
boucles ({% for %}). autoescape=True échappe automatiquement tout texte inséré :
un « <script> » venu d'une source s'affiche comme du texte et ne s'exécute jamais
(règle de sécurité n°7).
"""

import base64
import re
from functools import lru_cache
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

DOSSIER = Path(__file__).parent
DOSSIER_POLICES = DOSSIER / "static" / "polices"


@lru_cache(maxsize=1)
def css_polices() -> str:
    """Règles @font-face avec les fichiers woff2 incorporés (base64) : le numéro est un seul
    fichier, et il s'affiche pareil en ligne, hors ligne et en PDF. ~900 Ko par numéro.

    base64 : façon d'écrire des octets avec seulement des lettres et des chiffres, pour
    pouvoir glisser un fichier binaire (ici une police) dans du texte comme le HTML.
    """
    css = (DOSSIER_POLICES / "polices.css").read_text(encoding="utf-8")

    def incorporer(correspondance: re.Match) -> str:
        fichier = DOSSIER_POLICES / correspondance.group(1)
        donnees = base64.b64encode(fichier.read_bytes()).decode("ascii")
        return f"url(data:font/woff2;base64,{donnees})"

    return re.sub(r"url\(polices/([^)]+)\)", incorporer, css)

_env = Environment(
    loader=FileSystemLoader(DOSSIER / "templates"),
    autoescape=True,
    undefined=StrictUndefined,  # une donnée manquante provoque une erreur claire au lieu d'un trou silencieux
    trim_blocks=True,
    lstrip_blocks=True,
)


def _virgule(nombre) -> str:
    """9.8 -> "9,8" (écriture française) ; "–" si la faille n'a pas encore de score."""
    if nombre is None:
        return "–"
    return str(nombre).replace(".", ",")


def _lien(url: str) -> str:
    """Ne garde que les liens web. L'échappement ne suffit pas pour un lien : une adresse
    « javascript:... » venue d'un flux piégé exécuterait du code au clic (règle n°7)."""
    if url and url.strip().lower().startswith(("https://", "http://")):
        return url.strip()
    return "#"


_env.filters["virgule"] = _virgule
_env.filters["lien"] = _lien


def generer_html(numero: dict, chemin: Path) -> Path:
    """Écrit le numéro dans `chemin` et renvoie ce chemin."""
    # La feuille de style est insérée dans la page : un seul fichier à ouvrir ou envoyer
    css = (DOSSIER / "static" / "traces.css").read_text(encoding="utf-8")
    html = _env.get_template("numero.html").render(numero=numero, css=css, polices=css_polices())
    chemin.parent.mkdir(exist_ok=True)
    chemin.write_text(html, encoding="utf-8")
    return chemin
