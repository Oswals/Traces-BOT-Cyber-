"""
Interface commune des rédacteurs.

Un rédacteur transforme une Faille (données brutes) en textes pour le magazine.
Tous les rédacteurs (sans IA aujourd'hui, IA locale plus tard) offrent les mêmes
méthodes : la mise en page appelle redacteur.comprendre(faille) sans savoir
lequel elle utilise. On peut donc en changer sans toucher au reste.

ABC (Abstract Base Class) : une classe « modèle » qu'on ne peut pas utiliser
directement. Chaque méthode marquée @abstractmethod DOIT être écrite par les
classes qui en héritent, sinon Python refuse de les créer.
"""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass

from enrichissement.faille import Faille

PROVENANCES = ("source", "calcule", "bibliotheque", "ia_locale")


@dataclass
class Bloc:
    """Un morceau de texte du magazine, avec sa marque de provenance."""
    texte: str
    provenance: str     # une des PROVENANCES
    source: str         # ex. "CERT-FR", "CISA (EN)", "Glossaire CWE-78"
    lien: str = ""      # lien vers la source (règle n°4)
    langue: str = "fr"  # "en" si le texte est resté en anglais
    question: str = ""  # pour les points « Comprendre » : « C'est quoi ? »...

    def __post_init__(self):
        if self.provenance not in PROVENANCES:
            raise ValueError(f"provenance inconnue : {self.provenance!r}")

    def en_dict(self) -> dict:
        """Les gabarits Jinja2 reçoivent des dictionnaires."""
        return asdict(self)


class Redacteur(ABC):
    nom = "?"

    @abstractmethod
    def titre_une(self, faille: Faille) -> str:
        """Titre de la une, ex. « Ivanti EPMM : une faille critique déjà exploitée »."""

    @abstractmethod
    def titre_faille(self, faille: Faille) -> str:
        """Titre d'une fiche de la page « Failles exploitées »."""

    @abstractmethod
    def type_de_faille(self, faille: Faille) -> str:
        """Ex. « CWE-78 · Injection de commande système »."""

    @abstractmethod
    def resume(self, faille: Faille) -> Bloc:
        """Résumé de la une."""

    @abstractmethod
    def comprendre(self, faille: Faille) -> list[Bloc]:
        """Les 5 points : c'est quoi, qui est touché, gravité, attaquant, se protéger."""
