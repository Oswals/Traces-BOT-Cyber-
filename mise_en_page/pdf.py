"""
Export PDF A4 d'un numéro, avec le navigateur déjà installé (Edge ou Chrome) en mode
« sans fenêtre » : la même page HTML est imprimée en PDF, une page A4 par page du magazine.

Pas de bibliothèque PDF à installer : Edge est livré avec Windows. Si aucun navigateur n'est
trouvé, le HTML est quand même produit et l'erreur est journalisée.

Particularité Windows : le processus msedge.exe qu'on lance rend la main tout de suite et
confie l'impression à un processus enfant. On attend donc l'apparition du fichier PDF (et la
fin de son écriture) au lieu de se fier à la fin du processus. Le profil du navigateur est
gardé dans data/profil_pdf (jamais le profil personnel de l'utilisateur).
"""

import logging
import subprocess
import time
from pathlib import Path

import config

log = logging.getLogger(__name__)


def trouver_navigateur() -> Path | None:
    """Premier navigateur de config.NAVIGATEURS_PDF présent sur le PC."""
    for chemin in config.NAVIGATEURS_PDF:
        if Path(chemin).exists():
            return Path(chemin)
    return None


def exporter_pdf(html: Path, pdf: Path | None = None) -> Path | None:
    """Imprime `html` en PDF (même nom, extension .pdf par défaut). Renvoie le chemin, ou None."""
    pdf = pdf or html.with_suffix(".pdf")
    navigateur = trouver_navigateur()
    if navigateur is None:
        log.error("Pas de PDF : aucun navigateur trouvé (voir NAVIGATEURS_PDF dans config.py)")
        return None
    pdf.unlink(missing_ok=True)  # un ancien PDF ne doit pas passer pour le nouveau
    profil = config.DOSSIER_DATA / "profil_pdf"
    profil.mkdir(parents=True, exist_ok=True)

    commande = [
        str(navigateur), "--headless=new", "--disable-gpu", "--no-first-run",
        f"--user-data-dir={profil.resolve()}",
        f"--virtual-time-budget={config.PDF_ATTENTE_MS}",  # laisse le temps aux polices web
        "--no-pdf-header-footer",                           # pas de date ni d'adresse en marge
        f"--print-to-pdf={pdf.resolve()}",
        html.resolve().as_uri(),
    ]
    debut = time.monotonic()
    try:
        resultat = subprocess.run(commande, capture_output=True, text=True, timeout=config.PDF_TIMEOUT)
    except subprocess.TimeoutExpired:
        log.error("Pas de PDF : le navigateur n'a pas répondu en %d s", config.PDF_TIMEOUT)
        return None
    except OSError as erreur:
        log.error("Pas de PDF : impossible de lancer %s (%s)", navigateur, erreur)
        return None
    if resultat.returncode != 0:
        log.error("Pas de PDF : le navigateur a échoué (code %d) : %s",
                  resultat.returncode, resultat.stderr.strip()[-300:])
        return None

    if not _attendre_fichier(pdf, debut):
        log.error("Pas de PDF : %s n'est pas apparu en %d s", pdf.name, config.PDF_TIMEOUT)
        return None
    return pdf


def _attendre_fichier(fichier: Path, debut: float) -> bool:
    """Vrai quand le fichier existe et que sa taille ne bouge plus (écriture terminée)."""
    taille = -1
    while time.monotonic() - debut < config.PDF_TIMEOUT:
        if fichier.exists():
            nouvelle = fichier.stat().st_size
            if nouvelle == taille and nouvelle > 0:
                return True
            taille = nouvelle
        time.sleep(0.5)
    return False
