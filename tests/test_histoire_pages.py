"""Tests de la mise en page Histoire (hors ligne : aucun appel à Wikipédia ni à la NVD)."""

import json
import unittest
from datetime import date

import config
from unittest.mock import patch

from histoire import brouillon_ia, doutes, extraits, video
from histoire.choix import charger_episodes
from histoire.mise_en_forme import date_affichee, depassements_budget, page_episode, phrase_date, preparer
from mise_en_page import generer_html
from mise_en_page.exemple import NUMERO

TEXTE = """WannaCry was a worldwide cyberattack in May 2017. It targeted Windows computers.

== Background ==
EternalBlue is an exploit of Windows' SMB protocol.

== Attack ==
The attack began on 12 May 2017.

=== Defensive response ===
A kill switch was found.

== Impact ==
More than 200,000 computers were infected.

== References ==
Liste de références."""

ATTACK = {"id": "attack-C0001", "titre": "Opération X", "titre_en": "Opération X", "date": "2019-09-01",
          "precision_date": "mois", "categorie": "CYBERATTAQUE", "envergure": "moyen", "source": "MITRE ATT&CK",
          "langue": "en", "lien": "https://attack.mitre.org/campaigns/C0001/", "cves": [],
          "resume": "A campaign. <script>alert(1)</script>",
          "techniques": [{"id": f"T{1000 + i}", "nom": f"Technique {i}", "lien": "https://attack.mitre.org/"}
                         for i in range(15)]}


class TestExtraits(unittest.TestCase):
    def test_rubriques_reconnues(self):
        chapeau, sections = extraits.rubriques(TEXTE, 500)
        self.assertTrue(chapeau.startswith("WannaCry was"))
        self.assertEqual([s["cle"] for s in sections], ["contexte", "deroulement", "touches"])
        # La sous-partie « Defensive response » reste dans « Attack »
        self.assertIn("kill switch", sections[1]["texte"])
        # « References » n'est jamais une rubrique
        self.assertNotIn("Liste de références", " ".join(s["texte"] for s in sections))

    def test_couper_a_la_fin_d_une_phrase(self):
        self.assertEqual(extraits.couper_phrases("Une phrase. Une deuxième phrase longue.", 25), "Une phrase.")


class TestPreparer(unittest.TestCase):
    def test_dates(self):
        self.assertEqual(date_affichee("2017-05-12", "jour"), "12 mai 2017")
        self.assertEqual(date_affichee("2019-09-01", "mois"), "septembre 2019")
        self.assertEqual(date_affichee("2014-01-01", "année"), "2014")

    def test_phrase_date(self):
        self.assertEqual(phrase_date({"date": "2017-09-07", "precision_date": "jour", "type_date": "revelation"}),
                         "Révélé le 7 septembre 2017")
        self.assertEqual(phrase_date({"date": "2017-05-12", "precision_date": "jour", "type_date": "attaque"}),
                         "Survenu le 12 mai 2017")
        self.assertEqual(phrase_date({"date": "2019-09-01", "precision_date": "mois", "type_date": "attaque"}),
                         "Survenu en septembre 2019")

    def test_fiche_technique_attack(self):
        h = preparer({"candidat": ATTACK, "type": "technique", "anniversaire": False}, date(2026, 11, 10))
        self.assertFalse(h["double"])
        self.assertEqual(len(h["techniques"]), 12)
        self.assertEqual(h["techniques_reste"], 3)
        self.assertIn("MITRE", h["attribution"])

    def test_anniversaire(self):
        h = preparer({"candidat": ATTACK, "type": "technique", "anniversaire": True}, date(2026, 9, 1))
        self.assertEqual(h["anniversaire"], "Il y a 7 ans, jour pour jour")

    def test_texte_source_echappe(self):
        numero = dict(NUMERO, histoire=preparer({"candidat": ATTACK, "type": "technique", "anniversaire": False},
                                                date(2026, 11, 10)))
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as dossier:
            html = generer_html(numero, Path(dossier) / "t.html").read_text(encoding="utf-8")
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)


class TestEpisodes(unittest.TestCase):
    def test_wannacry_valide(self):
        fichier = config.DOSSIER_EPISODES / "wannacry-2017.json"
        episode = json.loads(fichier.read_text(encoding="utf-8"))
        self.assertIs(episode["verifie"], True)       # relu et validé le 2026-11-06
        self.assertEqual(episode["a_verifier"], [])
        self.assertEqual(len(episode["sections"]), 6)
        self.assertTrue(all(s["lien"].startswith("https://") for s in episode["sources"]))
        self.assertIn(episode["id"], {e["id"] for e in charger_episodes()})
        page = page_episode(episode, hors_ligne=True)
        self.assertTrue(page["double"])
        self.assertEqual(page["doutes"], [])          # validé : plus aucun doute affiché
        self.assertEqual(page["video"]["auteur"][:13], "Computerphile")

    def test_episode_non_relu_publie_avec_ses_doutes(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as dossier, patch.object(config, "DOSSIER_EPISODES", Path(dossier)):
            (Path(dossier) / "x.json").write_text('{"id": "wd-1", "verifie": false}', encoding="utf-8")
            self.assertEqual([e["id"] for e in charger_episodes()], ["wd-1"])   # publié quand même...
            self.assertEqual(charger_episodes(valides_seulement=True), [])    # ... mais pas « vérifié »
        episode = {"verifie": False, "a_verifier": ["Chiffre Europol à confirmer.", "x" * 400]}
        d = doutes.doutes_episode(episode)
        self.assertEqual(d[0], "Chiffre Europol à confirmer.")
        self.assertLessEqual(len(d[1]), doutes.LONGUEUR_MAX + 6)   # raccourci, avec « […] »

    def test_doutes_calcules_pour_une_decouverte(self):
        c = {"titre": "X", "titre_en": "X", "titre_fr": None, "langue": "en", "precision_date": "mois",
             "type_date": "revelation"}
        sections = [{"cle": "contexte"}, {"cle": "touches"}]
        d = doutes.doutes_decouverte(c, sections, texte_disponible=True)
        texte = " ".join(d)
        self.assertIn("Absent de la source : Déroulement, Cause technique, Conséquences, Enseignements.", d)
        self.assertEqual(len(d), doutes.NB_MAX)   # 7 doutes possibles, 4 gardés
        self.assertTrue(all(len(x) <= doutes.LONGUEUR_MAX + 6 for x in d))
        self.assertIn("mois près", texte)
        self.assertIn("révélation", texte)
        self.assertIn("anglais", texte)
        self.assertNotIn("Une seule page", texte)   # 5e doute : au-delà des 4 lignes affichées

    def test_video_morte_non_affichee(self):
        class Reponse:
            ok, status_code = False, 404
        with patch.object(video.requests, "get", return_value=Reponse()):
            self.assertIsNone(video.verifier_video({"titre": "T", "lien": "https://www.youtube.com/watch?v=x"}))
        self.assertIsNone(video.verifier_video({"titre": "T", "lien": "javascript:alert(1)"}))
        self.assertIsNone(video.verifier_video(None))

    def test_tous_les_episodes_respectent_le_budget(self):
        # Sinon la double page déborde du format A4 (mesuré avec outils/deborde.ps1)
        for fichier in sorted(config.DOSSIER_EPISODES.glob("*.json")):
            episode = json.loads(fichier.read_text(encoding="utf-8"))
            self.assertEqual(depassements_budget(episode), [], fichier.name)

    def test_budget_detecte_les_depassements(self):
        episode = {"chapeau": "x" * 301, "sections": [{"titre": "A", "texte": "y" * 481}],
                   "sources": [{"titre": "z" * 71}] * 7, "a_verifier": ["d" * 85]}
        problemes = depassements_budget(episode)
        self.assertEqual(len(problemes), 11)   # chapeau, rubrique, 7 titres, sources, doute

    def test_brouillon_ia_ne_fait_rien(self):
        self.assertIsNone(brouillon_ia.rediger_brouillon({"id": "x"}, "texte"))


if __name__ == "__main__":
    unittest.main()
