"""
Tests de l'étape 6 (sans Internet). Lancer depuis la racine du projet :
    python -m unittest -v

unittest est le module de tests intégré à Python : chaque méthode qui commence
par test_ est lancée automatiquement, et assertEqual(a, b) échoue si a != b.
"""

import json
import unittest
from pathlib import Path

from redaction import cvss
from enrichissement.bulletins import lire_bulletin, texte_brut

V31_CRITIQUE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class TestCvss(unittest.TestCase):

    def test_profil_v31(self):
        cases = cvss.profil(V31_CRITIQUE)
        self.assertEqual(len(cases), 8)
        self.assertEqual(cases[0], {"critere": "Accès", "valeur": "Par Internet", "niveau": "critique"})
        self.assertEqual(cases[5]["valeur"], "Perte totale")

    def test_phrase_v31(self):
        self.assertEqual(cvss.phrase_gravite(V31_CRITIQUE),
                         "exploitable par Internet, sans compte ni action de la victime, avec une perte "
                         "totale de confidentialité, d'intégrité et de disponibilité")

    def test_phrase_impacts_melanges(self):
        phrase = cvss.phrase_gravite("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:H/I:L/A:N")
        self.assertIn("avec un accès à la machine", phrase)
        self.assertIn("avec un simple compte utilisateur", phrase)
        self.assertIn("difficile à exploiter", phrase)
        self.assertIn("une perte totale de confidentialité et une perte partielle d'intégrité", phrase)
        self.assertIn("déborder sur d'autres systèmes", phrase)

    def test_v40_ramenee_a_v31(self):
        codes = cvss.lire_vecteur("CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:A/VC:H/VI:N/VA:N/SC:L/SI:N/SA:N")
        self.assertEqual(codes["AC"], "H")  # AT:P = conditions préalables -> difficulté élevée
        self.assertEqual(codes["UI"], "R")
        self.assertEqual(codes["S"], "C")   # impact sur d'autres systèmes (SC:L)

    def test_v20(self):
        cases = cvss.profil("AV:N/AC:M/Au:N/C:P/I:P/A:C")
        valeurs = {c["critere"]: c["valeur"] for c in cases}
        self.assertEqual(valeurs["Compte nécessaire"], "Aucun")
        self.assertEqual(valeurs["Disponibilité"], "Perte totale")
        self.assertEqual(valeurs["Portée"], "Non précisé")  # n'existe pas en 2.0

    def test_vecteur_vide_ou_illisible(self):
        self.assertEqual(cvss.profil(""), [])
        self.assertEqual(cvss.phrase_gravite(""), "")
        self.assertEqual(cvss.profil("n'importe quoi")[0]["valeur"], "Non précisé")


class TestBulletinCertfr(unittest.TestCase):

    def test_texte_brut(self):
        md = "<span>**[Mise à jour]**</span><br/>Texte *important*\n- premier point\n1. second point;"
        self.assertEqual(texte_brut(md), "[Mise à jour]. Texte important. premier point. second point;")

    def test_lire_bulletin(self):
        brut = {
            "reference": "CERTFR-2099-AVI-0001",
            "summary": "De multiples vulnérabilités ont été découvertes.",
            "affected_systems": [{"description": "Acme versions antérieures à 2.0"}],
            "risks": [{"description": "Exécution de code arbitraire à distance"}],
            "content": "## Contournements provisoires\nDésactiver le module.\n\n## Solutions\n\n"
                       "Se référer au bulletin de sécurité de l'éditeur (cf. section Documentation).",
            "cves": [{"name": "CVE-2099-0002"}, {"name": "CVE-2099-0001"}],
            "vendor_advisories": [{"title": "Bulletin Acme", "url": "https://example.org/"}],
        }
        b = lire_bulletin(brut)
        self.assertEqual(b.systemes, ["Acme versions antérieures à 2.0"])
        self.assertEqual(b.risques, ["Exécution de code arbitraire à distance"])
        self.assertTrue(b.solution.startswith("Se référer"))
        self.assertEqual(b.contournement, "Désactiver le module.")
        self.assertEqual(b.cves, ["CVE-2099-0001", "CVE-2099-0002"])


class TestGlossaire(unittest.TestCase):

    def test_format(self):
        donnees = json.loads((Path("redaction") / "glossaire_cwe.json").read_text(encoding="utf-8"))
        for cle, fiche in donnees.items():
            if cle.startswith("_"):
                continue
            with self.subTest(cwe=cle):
                self.assertRegex(cle, r"^CWE-\d+$")
                self.assertTrue(fiche["nom"] and fiche["explication"])
                self.assertTrue(fiche["lien"].endswith(f"/{cle.removeprefix('CWE-')}.html"))


if __name__ == "__main__":
    unittest.main()
