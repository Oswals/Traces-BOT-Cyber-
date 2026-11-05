"""
Traduction d'un vecteur CVSS en français.

Un vecteur CVSS est une suite de critères codés, par exemple
    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
AV:N veut dire « Attack Vector : Network » (attaquable par le réseau), C:H
« Confidentialité : High » (perte totale), etc. Ce module en tire :
  - profil()        : les 8 cases du « profil de la faille », colorées selon le danger
  - phrase_gravite(): une phrase lisible pour le point « Gravité »

Versions gérées : 3.0 / 3.1 (les plus courantes), 4.0 et 2.0. Pour ne pas écrire
trois traductions, les versions 4.0 et 2.0 sont d'abord ramenées aux codes de la 3.1.
"""

# Pour chaque critère : (libellé de la case, {code: (valeur affichée, niveau de danger)})
# Le niveau colore la case : "critique" = le plus favorable à l'attaquant.
IMPACT = {"H": ("Perte totale", "haute"), "L": ("Perte partielle", "moyenne"), "N": ("Aucun impact", "faible")}

CRITERES = {
    "AV": ("Accès", {"N": ("Par Internet", "critique"), "A": ("Réseau local", "haute"),
                     "L": ("Accès à la machine", "moyenne"), "P": ("Contact physique", "faible")}),
    "AC": ("Difficulté", {"L": ("Faible", "critique"), "H": ("Élevée", "moyenne")}),
    "PR": ("Compte nécessaire", {"N": ("Aucun", "critique"), "L": ("Simple utilisateur", "haute"),
                                 "H": ("Administrateur", "moyenne")}),
    "UI": ("Action de la victime", {"N": ("Aucune", "critique"), "R": ("Nécessaire", "moyenne")}),
    "S":  ("Portée", {"U": ("Limitée au produit", "moyenne"), "C": ("Déborde sur d'autres systèmes", "haute")}),
    "C":  ("Confidentialité", IMPACT),
    "I":  ("Intégrité", IMPACT),
    "A":  ("Disponibilité", IMPACT),
}
NON_PRECISE = ("Non précisé", "inconnu")


def lire_vecteur(vecteur: str) -> dict[str, str]:
    """"CVSS:3.1/AV:N/AC:L/..." -> {"version": "3.1", "AV": "N", "AC": "L", ...} (codes de la 3.1)."""
    if not vecteur:
        return {}
    morceaux = vecteur.split("/")
    if morceaux[0].startswith("CVSS:"):
        version = morceaux.pop(0).removeprefix("CVSS:")
    else:
        version = "2.0"  # les vecteurs 2.0 n'ont pas de préfixe : "AV:N/AC:L/Au:N/C:P/I:P/A:P"
    codes = dict(m.split(":", 1) for m in morceaux if ":" in m)

    if version.startswith("4"):
        codes = _depuis_v4(codes)
    elif version.startswith("2"):
        codes = _depuis_v2(codes)
    codes["version"] = version
    return codes


def profil(vecteur: str) -> list[dict]:
    """Les 8 cases du profil ; liste vide si le vecteur est absent ou illisible."""
    codes = lire_vecteur(vecteur)
    if not codes:
        return []
    cases = []
    for code, (critere, valeurs) in CRITERES.items():
        valeur, niveau = valeurs.get(codes.get(code, ""), NON_PRECISE)
        cases.append({"critere": critere, "valeur": valeur, "niveau": niveau})
    return cases


def phrase_gravite(vecteur: str) -> str:
    """Ex. « exploitable par Internet, sans compte ni action de la victime, avec une perte
    totale de confidentialité, d'intégrité et de disponibilité » ("" si vecteur illisible)."""
    c = lire_vecteur(vecteur)
    if not c:
        return ""
    morceaux = []

    acces = {"N": "exploitable par Internet", "A": "exploitable depuis le réseau local",
             "L": "exploitable avec un accès à la machine", "P": "exploitable avec un contact physique"}
    if c.get("AV") in acces:
        morceaux.append(acces[c["AV"]])

    # Conditions : compte nécessaire et action de la victime
    compte = {"N": "sans compte", "L": "avec un simple compte utilisateur", "H": "avec un compte administrateur"}
    if c.get("PR") == "N" and c.get("UI") == "N":
        morceaux.append("sans compte ni action de la victime")
    else:
        if c.get("PR") in compte:
            morceaux.append(compte[c["PR"]])
        if c.get("UI") == "R":
            morceaux.append("à condition que la victime fasse une action (ouvrir un fichier, cliquer…)")
    if c.get("AC") == "H":
        morceaux.append("mais difficile à exploiter")

    # Impacts, regroupés par ampleur : « perte totale de X et Y, et perte partielle de Z »
    noms = {"C": "de confidentialité", "I": "d'intégrité", "A": "de disponibilité"}
    totale = [noms[k] for k in "CIA" if c.get(k) == "H"]
    partielle = [noms[k] for k in "CIA" if c.get(k) == "L"]
    impacts = []
    if totale:
        impacts.append("une perte totale " + _liste(totale))
    if partielle:
        impacts.append("une perte partielle " + _liste(partielle))
    if impacts:
        morceaux.append("avec " + " et ".join(impacts))
    if c.get("S") == "C":
        morceaux.append("qui peut déborder sur d'autres systèmes")

    return ", ".join(morceaux)


# --- Conversion des autres versions vers les codes de la 3.1 ------------------------

def _depuis_v4(v4: dict) -> dict:
    codes = {"AV": v4.get("AV", ""), "PR": v4.get("PR", "")}
    # 4.0 sépare la difficulté (AC) et les conditions préalables (AT) : l'une ou l'autre rend l'attaque difficile
    if v4.get("AC") or v4.get("AT"):
        codes["AC"] = "H" if v4.get("AC") == "H" or v4.get("AT") == "P" else "L"
    # Action de la victime : N = aucune ; P (passive) et A (active) = une action est nécessaire
    if v4.get("UI"):
        codes["UI"] = "N" if v4["UI"] == "N" else "R"
    # Impacts sur le produit lui-même (VC, VI, VA) et sur les autres systèmes (SC, SI, SA)
    codes.update({"C": v4.get("VC", ""), "I": v4.get("VI", ""), "A": v4.get("VA", "")})
    autres = [v4.get(k) for k in ("SC", "SI", "SA") if v4.get(k)]
    if autres:
        codes["S"] = "C" if any(v != "N" for v in autres) else "U"
    return codes


def _depuis_v2(v2: dict) -> dict:
    # 2.0 : Au = nombre d'authentifications, impacts N / P (partiel) / C (complet)
    # Elle ne connaît ni l'action de la victime ni la portée : ces cases restent « Non précisé »
    impact = {"N": "N", "P": "L", "C": "H"}
    return {
        "AV": v2.get("AV", ""),
        "AC": {"L": "L", "M": "H", "H": "H"}.get(v2.get("AC", ""), ""),
        "PR": {"N": "N", "S": "L", "M": "L"}.get(v2.get("Au", ""), ""),
        "C": impact.get(v2.get("C", ""), ""),
        "I": impact.get(v2.get("I", ""), ""),
        "A": impact.get(v2.get("A", ""), ""),
    }


def _liste(elements: list[str]) -> str:
    """["a", "b", "c"] -> "a, b et c"."""
    if len(elements) == 1:
        return elements[0]
    return ", ".join(elements[:-1]) + " et " + elements[-1]
