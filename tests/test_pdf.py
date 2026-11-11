"""Tests de l'export PDF, hors ligne (aucun navigateur n'est lancé)."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import config
from mise_en_page import pdf


class TestPdf(unittest.TestCase):
    def test_sans_navigateur_pas_de_pdf_mais_pas_de_plantage(self):
        with patch.object(config, "NAVIGATEURS_PDF", [r"C:\nulle\part\navigateur.exe"]):
            self.assertIsNone(pdf.trouver_navigateur())
            self.assertIsNone(pdf.exporter_pdf(Path("sortie/traces_demo.html")))

    def test_premier_navigateur_existant(self):
        with tempfile.TemporaryDirectory() as dossier:
            faux = Path(dossier) / "edge.exe"
            faux.write_bytes(b"")
            with patch.object(config, "NAVIGATEURS_PDF", [r"C:\nulle\part\a.exe", str(faux)]):
                self.assertEqual(pdf.trouver_navigateur(), faux)

    def test_commande_imprime_en_a4_sans_en_tete(self):
        """La commande passée au navigateur contient bien les options attendues."""
        appels = []

        class Resultat:
            returncode, stderr = 0, ""

        def faux_run(commande, **_):
            appels.append(commande)
            Path(commande[-2].split("=", 1)[1]).write_bytes(b"%PDF-1.4")  # simule le fichier produit
            return Resultat()

        with tempfile.TemporaryDirectory() as dossier:
            html = Path(dossier) / "x.html"
            html.write_text("<html></html>", encoding="utf-8")
            with patch.object(config, "NAVIGATEURS_PDF", [str(html)]), patch.object(pdf.subprocess, "run", faux_run):
                self.assertEqual(pdf.exporter_pdf(html), html.with_suffix(".pdf"))
        commande = appels[0]
        self.assertIn("--headless=new", commande)
        self.assertIn("--no-pdf-header-footer", commande)
        self.assertTrue(commande[-1].startswith("file:///"))


if __name__ == "__main__":
    unittest.main()
