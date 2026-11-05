"""
Tests de la rubrique Arnaques (sans Internet) : python -m unittest -v

patch (de unittest.mock) remplace temporairement un réglage, ici l'emplacement
de arnaque_manuelle.json, pour ne jamais toucher au vrai dossier data/.
"""

import json
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import config
from collecteurs.article import Article
from selection.arnaque import (CHAMPS_FICHE, charger_fiches, choisir_arnaque, fiche_la_plus_proche)


def article_presse(titre: str, jours: int = 0) -> Article:
    return Article(titre=titre, lien=f"https://example.org/{abs(hash(titre))}", source="Zataz",
                   type_source="presse", langue="fr",
                   date=datetime.now(timezone.utc) - timedelta(days=jours))


class TestArnaque(unittest.TestCase):

    def setUp(self):
        # Dossier temporaire supprimé automatiquement à la fin de chaque test
        self.dossier = tempfile.TemporaryDirectory()
        self.addCleanup(self.dossier.cleanup)
        self.manuelle = Path(self.dossier.name) / "arnaque_manuelle.json"
        patcher = patch.object(config, "FICHIER_ARNAQUE_MANUELLE", self.manuelle)
        patcher.start()
        self.addCleanup(patcher.stop)

    def ecrire_manuelle(self, jour: date, **champs):
        donnees = {"date": jour.isoformat(), "titre": "Alerte saisie à la main",
                   "lien": "https://example.org/alerte", **champs}
        self.manuelle.write_text(json.dumps(donnees), encoding="utf-8")

    def test_1_alerte_manuelle_prioritaire(self):
        self.ecrire_manuelle(date.today(), fiche="sextorsion")
        choix = choisir_arnaque([article_presse("Une arnaque au faux conseiller")], numero=1)
        self.assertEqual(choix.mode, "manuelle")
        self.assertEqual(choix.fiche["id"], "sextorsion")

    def test_1_alerte_manuelle_perimee(self):
        self.ecrire_manuelle(date.today() - timedelta(days=config.ARNAQUE_MANUELLE_JOURS + 1))
        choix = choisir_arnaque([article_presse("Une arnaque au faux conseiller")], numero=1)
        self.assertEqual(choix.mode, "presse")  # la manuelle est ignorée, on passe au niveau 2

    def test_2_presse_et_fiche_la_plus_proche(self):
        articles = [article_presse("Le ministère publie son budget"),
                    article_presse("Vague d'arnaques au faux conseiller bancaire")]
        choix = choisir_arnaque(articles, numero=1)
        self.assertEqual(choix.mode, "presse")
        self.assertEqual(choix.alerte["titre"], "Vague d'arnaques au faux conseiller bancaire")
        self.assertEqual(choix.fiche["id"], "faux-conseiller-bancaire")

    def test_2_presse_trop_ancienne(self):
        vieux = article_presse("Phishing : une campagne massive", jours=config.ARNAQUE_PRESSE_JOURS + 2)
        self.assertEqual(choisir_arnaque([vieux], numero=1).mode, "fiche")

    def test_3_fiche_du_numero_en_rotation(self):
        fiches = charger_fiches()
        ids = {choisir_arnaque([], numero=n).fiche["id"] for n in range(len(fiches))}
        self.assertEqual(len(ids), len(fiches))  # chaque fiche passe une fois sur un cycle

    def test_aucun_mot_cle_fiche_par_defaut(self):
        self.assertEqual(fiche_la_plus_proche("texte sans rapport", charger_fiches())["id"], "hameconnage")


class TestBibliothequeArnaques(unittest.TestCase):

    def test_fiches_completes(self):
        chemins = sorted(config.DOSSIER_ARNAQUES.glob("*.json"))
        self.assertGreaterEqual(len(chemins), 3)
        for chemin in chemins:
            with self.subTest(fiche=chemin.name):
                fiche = json.loads(chemin.read_text(encoding="utf-8"))
                for champ in CHAMPS_FICHE:
                    self.assertTrue(fiche.get(champ), f"champ « {champ} » vide ou absent")
                self.assertEqual(fiche["id"], chemin.stem)  # le nom du fichier = l'identifiant
                for contact in fiche["signaler"]:
                    self.assertTrue(contact["lien"] == "" or contact["lien"].startswith("https://"))


if __name__ == "__main__":
    unittest.main()
