"""
Format d'une faille enrichie : une CVE, tous les articles qui la citent,
sa fiche NVD et, si elle est activement exploitée, son entrée CISA KEV.
"""

from dataclasses import dataclass, field

from collecteurs.article import Article


@dataclass
class FicheNVD:
    score: float | None       # score CVSS de base (0 à 10), None si pas encore évalué
    gravite: str              # libellé NVD : LOW, MEDIUM, HIGH, CRITICAL
    vecteur: str              # ex. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    version_cvss: str         # "3.1", "3.0", "4.0" ou "2.0"
    cwes: list[str]           # types de faille, ex. ["CWE-79"]
    produits: list[str]       # ex. ["Ivanti Connect Secure"]
    description: str         # description officielle, en anglais


@dataclass
class Faille:
    cve: str
    articles: list[Article] = field(default_factory=list)  # toutes les sources qui la citent
    nvd: FicheNVD | None = None   # None si la NVD ne la connaît pas (encore)
    kev: Article | None = None    # entrée CISA KEV, None si pas d'exploitation connue

    # Une property se lit comme un champ (faille.exploitee) mais est calculée à chaque lecture
    @property
    def exploitee(self) -> bool:
        return self.kev is not None

    @property
    def score(self) -> float | None:
        return self.nvd.score if self.nvd else None

    @property
    def sources(self) -> list[str]:
        """Noms des sources qui citent la faille, sans doublon."""
        return sorted({article.source for article in self.articles})
