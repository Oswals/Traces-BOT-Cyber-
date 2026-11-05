"""
Transforme un numéro (dictionnaire) en fichier HTML, avec les gabarits Jinja2.

Jinja2 remplit des gabarits HTML contenant des « trous » ({{ variable }}) et des
boucles ({% for %}). autoescape=True échappe automatiquement tout texte inséré :
un « <script> » venu d'une source s'affiche comme du texte et ne s'exécute jamais
(règle de sécurité n°7).
"""

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, StrictUndefined

DOSSIER = Path(__file__).parent

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
    html = _env.get_template("numero.html").render(numero=numero, css=css)
    chemin.parent.mkdir(exist_ok=True)
    chemin.write_text(html, encoding="utf-8")
    return chemin
