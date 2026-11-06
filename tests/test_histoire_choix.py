"""Tests du choix de l'événement du jour (aucune requête réseau, aucun fichier écrit)."""

import unittest
from datetime import date, timedelta

from histoire.choix import choisir, entree_publie, envergure_du_jour

LUNDI = date(2026, 11, 9)   # jour « grand » avec les réglages par défaut (lundi, jeudi)
MARDI = date(2026, 11, 10)  # jour « moyen »


def cand(id_, categorie, envergure="moyen", date_ev="2015-03-01", precision="mois", langues=10):
    return {"id": id_, "titre": id_, "titre_en": id_, "categorie": categorie, "envergure": envergure,
            "date": date_ev, "precision_date": precision, "langues": langues, "vues": 0}


def publie(id_, jour, categorie, envergure="moyen", type_="technique"):
    return {"id": id_, "titre_normalise": id_.lower(), "date": jour.isoformat(), "categorie": categorie,
            "envergure": envergure, "type": type_}


class TestChoix(unittest.TestCase):
    def test_rythme(self):
        self.assertEqual(envergure_du_jour(LUNDI), "grand")
        self.assertEqual(envergure_du_jour(MARDI), "moyen")

    def test_jamais_la_meme_categorie_que_la_veille(self):
        candidats = [cand("a", "BUG"), cand("b", "PANNE")]
        publies = [publie("x", MARDI - timedelta(days=1), "BUG", "grand", "découverte")]
        self.assertEqual(choisir(MARDI, candidats, [], publies)["candidat"]["id"], "b")

    def test_deja_publie_par_id_ou_par_titre(self):
        candidats = [cand("A", "BUG"), cand("B", "BUG")]
        publies = [publie("autre-source", date(2026, 1, 1), "BUG")]
        publies[0]["titre_normalise"] = "a"   # même événement, venu d'une autre source
        self.assertEqual(choisir(MARDI, candidats, [], publies)["candidat"]["id"], "B")

    def test_anniversaire_prioritaire(self):
        candidats = [cand("a", "BUG"), cand("anniv", "BUG", date_ev="2016-11-10", precision="jour")]
        choix = choisir(MARDI, candidats, [], [])
        self.assertEqual(choix["candidat"]["id"], "anniv")
        self.assertTrue(choix["anniversaire"])

    def test_episode_complet_avant_decouverte(self):
        candidats = [cand("wd-1", "CYBERATTAQUE", "grand", langues=40), cand("wd-2", "BUG", "grand", langues=10)]
        episodes = [{"id": "wd-2", "titre": "wd-2", "categorie": "BUG", "date": "2014-04-07", "verifie": True}]
        choix = choisir(LUNDI, candidats, episodes, [])
        self.assertEqual((choix["candidat"]["id"], choix["type"]), ("wd-2", "complet"))

    def test_grand_sans_episode_donne_une_decouverte(self):
        choix = choisir(LUNDI, [cand("wd-1", "BUG", "grand")], [], [])
        self.assertEqual(choix["type"], "découverte")

    def test_tout_publie_on_reprend_le_plus_ancien(self):
        candidats = [cand("a", "BUG"), cand("b", "BUG")]
        publies = [publie("a", date(2026, 3, 1), "BUG"), publie("b", date(2026, 1, 1), "BUG")]
        self.assertEqual(choisir(MARDI, candidats, [], publies)["candidat"]["id"], "b")

    def test_relancer_le_meme_jour_redonne_le_meme_choix(self):
        candidats = [cand("a", "BUG"), cand("b", "PANNE")]
        premier = choisir(MARDI, candidats, [], [])
        publies = [entree_publie(MARDI, premier)]
        self.assertEqual(choisir(MARDI, candidats, [], publies)["candidat"]["id"], premier["candidat"]["id"])

    def test_choix_deterministe(self):
        candidats = [cand(str(i), "BUG") for i in range(20)]
        self.assertEqual(choisir(MARDI, candidats, [], [])["candidat"]["id"],
                         choisir(MARDI, candidats, [], [])["candidat"]["id"])


if __name__ == "__main__":
    unittest.main()
