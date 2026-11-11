"""Tests du rendu HTML : polices incorporées, aucune dépendance réseau."""

import tempfile
import unittest
from pathlib import Path

from mise_en_page import generer_html
from mise_en_page.exemple import NUMERO
from mise_en_page.rendu import css_polices


class TestRendu(unittest.TestCase):
    def test_polices_incorporees_sans_google_fonts(self):
        with tempfile.TemporaryDirectory() as dossier:
            html = generer_html(NUMERO, Path(dossier) / "n.html").read_text(encoding="utf-8")
        self.assertNotIn("fonts.googleapis.com", html)
        self.assertNotIn("fonts.gstatic.com", html)
        self.assertEqual(html.count("@font-face"), 10)   # 3 familles, latin + latin-ext
        self.assertIn("data:font/woff2;base64,", html)
        self.assertNotIn("url(polices/", html)           # tous les fichiers ont été incorporés

    def test_toutes_les_familles(self):
        css = css_polices()
        for famille in ("Archivo", "IBM Plex Mono", "Source Serif 4"):
            self.assertIn(f"font-family: '{famille}'", css)


if __name__ == "__main__":
    unittest.main()
