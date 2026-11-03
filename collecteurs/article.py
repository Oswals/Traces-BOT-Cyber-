"""
Format commun : tous les collecteurs renvoient des objets Article.
Le reste du pipeline ne sait rien des sources, il ne manipule que des Article.
"""

import html
import re
from dataclasses import dataclass, field
from datetime import datetime

# officiel = autorité publique (CERT-FR, Cybermalveillance)
# base     = base de données de failles (CISA KEV)
# presse   = média
TYPES_SOURCE = ("officiel", "base", "presse")

# Une CVE s'écrit CVE-année-numéro, le numéro ayant 4 chiffres ou plus
MOTIF_CVE = re.compile(r"CVE-\d{4}-\d{4,7}")


@dataclass
class Article:
    titre: str
    lien: str
    source: str                   # nom lisible : "CERT-FR", "BleepingComputer"...
    type_source: str              # une des valeurs de TYPES_SOURCE
    date: datetime | None         # en UTC ; None si la source ne la donne pas
    texte_source: str = ""        # texte brut (sans HTML) fourni par la source
    cves: list[str] = field(default_factory=list)
    langue: str = "fr"            # "fr" ou "en"
    details: dict = field(default_factory=dict)  # infos propres à une source (ex. produit pour la CISA)

    def __post_init__(self):
        # Exécuté automatiquement juste après la création de l'objet
        if self.type_source not in TYPES_SOURCE:
            raise ValueError(f"type_source inconnu : {self.type_source!r} "
                             f"(attendu : {', '.join(TYPES_SOURCE)})")
        if not self.cves:
            self.cves = extraire_cves(self.titre + " " + self.texte_source)


def extraire_cves(texte: str) -> list[str]:
    """Liste triée et sans doublon des CVE citées dans un texte."""
    return sorted(set(MOTIF_CVE.findall(texte)))


def nettoyer_html(texte: str) -> str:
    """Transforme un extrait HTML de flux RSS en texte brut sur une ligne."""
    # Certains flux encodent le HTML deux fois (&amp;lt;p&amp;gt;) : on décode jusqu'à ce que ça ne change plus
    precedent = None
    while texte != precedent:
        precedent, texte = texte, html.unescape(texte)
    texte = re.sub(r"<[^>]+>", " ", texte)    # retire les balises <...>
    return re.sub(r"\s+", " ", texte).strip()  # espaces multiples -> un seul
