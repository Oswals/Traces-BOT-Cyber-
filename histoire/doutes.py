"""
Points de doute d'une page Histoire : ce dont le magazine n'est PAS sûr, dit clairement
en bas de page au lieu de bloquer la publication (circuit décidé le 2026-11-11).

- Épisode rédigé : la liste `a_verifier` écrite par l'auteur (marque BIBLIOTHÈQUE).
- Fiche découverte ou technique : doutes DÉDUITS des données (marque CALCULÉ) :
  rubriques absentes de la source, date imprécise ou de révélation, texte en anglais,
  une seule page source, valeurs fixées à la main dans config.py.

Aucun doute n'est inventé : chaque phrase correspond à un fait vérifiable dans les données.
"""

import config

from .extraits import RUBRIQUES, couper_phrases

NB_MAX = 4            # lignes affichées au plus : c'est une section miniature
LONGUEUR_MAX = 84     # caractères : une seule ligne en 12 px mono sur la largeur de la page


def _limiter(doutes: list[str]) -> list[str]:
    return [couper_phrases(d, LONGUEUR_MAX) for d in doutes[:NB_MAX]]


def doutes_episode(episode: dict) -> list[str]:
    """Un épisode validé n'a plus de doute ; sinon, la liste laissée par l'auteur."""
    if episode.get("verifie") is True:
        return []
    return _limiter(list(episode.get("a_verifier", [])))


def _doutes_communs(c: dict) -> list[str]:
    """Doutes valables pour toute fiche construite à partir du catalogue."""
    doutes = []
    titre = c.get("titre_en") or c.get("titre", "")
    if c.get("precision_date") == "mois":
        doutes.append("Date connue au mois près seulement : le jour exact n'est pas donné par la source.")
    elif c.get("precision_date") == "année":
        doutes.append("Date connue à l'année près seulement.")
    if c.get("type_date") == "revelation":
        doutes.append("La date est celle de la révélation publique, pas celle des faits eux-mêmes.")
    if titre in config.HISTOIRE_DATES_MANUELLES:
        doutes.append("Date saisie à la main dans config.py : Wikidata n'en donne pas.")
    if titre in config.HISTOIRE_CATEGORIE_FORCEE:
        doutes.append("Catégorie fixée à la main dans config.py.")
    if titre in config.HISTOIRE_FORCER_GRAND:
        doutes.append("Envergure « grand » fixée à la main : les seuils de notoriété ne sont pas atteints.")
    return doutes


def doutes_decouverte(c: dict, sections: list[dict], texte_disponible: bool) -> list[str]:
    doutes = []
    if not texte_disponible:
        doutes.append("Texte de la source indisponible aujourd'hui : seuls les repères sont affichés.")
    else:
        trouvees = {s["cle"] for s in sections}
        absentes = [titre for cle, titre, _ in RUBRIQUES if cle not in trouvees]
        if absentes:
            doutes.append("Absent de la source : " + ", ".join(absentes) + ".")
    doutes += _doutes_communs(c)   # les doutes sur la date passent avant ceux sur la langue
    if c.get("langue", "fr") != "fr":
        doutes.append("Texte en anglais, non traduit.")
    if not (c.get("titre_fr") and c.get("titre_en")):
        doutes.append("Une seule page Wikipédia (FR ou EN) : pas de recoupement entre les deux langues.")
    return _limiter(doutes)


def doutes_technique(c: dict) -> list[str]:
    doutes = []
    source = c.get("source", "")
    if source == "CISA KEV":
        doutes.append("La date est celle de la publication de la CVE : les attaques réelles sont postérieures.")
        doutes.append("Résumé officiel de la CISA, très court : il ne raconte pas les attaques.")
    elif source == "MITRE ATT&CK":
        doutes.append("Description de MITRE, centrée sur les techniques : les victimes et les conséquences "
                      "sont peu détaillées.")
    if c.get("langue", "fr") != "fr":
        doutes.append("Texte en anglais, non traduit.")
    if source == "Wikipédia" and not (c.get("titre_fr") and c.get("titre_en")):
        doutes.append("Une seule page Wikipédia (FR ou EN) : pas de recoupement entre les deux langues.")
    communs = [d for d in _doutes_communs(c)
               if not (source == "CISA KEV" and d.startswith("La date est celle de la révélation"))]
    return _limiter(doutes + communs)
