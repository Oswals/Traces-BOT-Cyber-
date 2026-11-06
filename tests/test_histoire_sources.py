"""Tests hors ligne des sources de la rubrique Histoire (aucune requête réseau)."""

import unittest
from datetime import date
from unittest.mock import patch

import config
from histoire import attack, wikimedia
from histoire.catalogue import _candidat_wikipedia, dedoublonner, envergure
from histoire.outils import normaliser


def claim(temps, precision=11):
    return [{"mainsnak": {"datavalue": {"value": {"time": temps, "precision": precision}}}}]


class TestWikimedia(unittest.TestCase):
    def test_pas_de_requete_sans_contact(self):
        with patch.object(config, "TRACES_CONTACT", ""):
            with self.assertRaises(wikimedia.ContactManquant):
                wikimedia.user_agent()

    def test_user_agent_contient_le_contact(self):
        with patch.object(config, "TRACES_CONTACT", "https://exemple.org/traces"):
            self.assertIn("https://exemple.org/traces", wikimedia.user_agent())

    def test_date_preferee_et_precision(self):
        # P585 (date) passe avant P580 (début)
        claims = {"P580": claim("+2016-01-01T00:00:00Z"), "P585": claim("+2017-05-12T00:00:00Z")}
        self.assertEqual(wikimedia._date_wikidata(claims), ("2017-05-12", 11))

    def test_date_a_l_annee(self):
        self.assertEqual(wikimedia._date_wikidata({"P580": claim("+2014-00-00T00:00:00Z", 9)}),
                         ("2014-01-01", 9))

    def test_sans_date(self):
        self.assertIsNone(wikimedia._date_wikidata({"P571": claim("+2005-01-01T00:00:00Z")}))

    def test_pages_avec_qid(self):
        morceau = {"query": {"pages": [
            {"ns": 0, "title": "WannaCry ransomware attack", "pageprops": {"wikibase_item": "Q29908721"}},
            {"ns": 14, "title": "Category:Ransomware", "pageprops": {"wikibase_item": "Q1"}},
            {"ns": 0, "title": "Sans Wikidata"}]}}
        self.assertEqual(wikimedia._pages_avec_qid(morceau), {"WannaCry ransomware attack": "Q29908721"})


class TestEnvergure(unittest.TestCase):
    def ev(self, titre="X", langues=5, vues=10_000):
        return {"titre": titre, "titre_en": titre, "langues": langues, "vues": vues}

    def test_seuils(self):
        self.assertEqual(envergure(self.ev(langues=25)), "grand")
        self.assertEqual(envergure(self.ev(vues=150_000)), "grand")
        self.assertEqual(envergure(self.ev()), "moyen")
        self.assertEqual(envergure(self.ev(vues=500)), "écarté")

    def test_forcage(self):
        self.assertEqual(envergure(self.ev("2017 Equifax data breach", langues=1)), "grand")


class TestAttack(unittest.TestCase):
    def test_nettoyer_description(self):
        texte = "Campagne de [Sandworm](https://attack.mitre.org/groups/G0034) contre l'Ukraine.(Citation: ESET 2017)"
        self.assertEqual(attack.nettoyer_description(texte), "Campagne de Sandworm contre l'Ukraine.")


class TestCatalogue(unittest.TestCase):
    def info(self, natures, titre="2021 Facebook outage", date="2021-10-04"):
        return {"titre_en": titre, "titre_fr": None, "date": date, "precision": 11, "langues": 21,
                "natures": natures, "cves": []}

    def test_nature_donne_la_categorie(self):
        c = _candidat_wikipedia("Q1", self.info(["Q28914147"]), ["CYBERATTAQUE"], date(2026, 11, 6))
        self.assertEqual(c["categorie"], "PANNE")

    def test_nature_hors_sujet_ecartee(self):
        # Q11424 = film : pas un événement cyber, même si la source est une liste de cyberattaques
        self.assertIsNone(_candidat_wikipedia("Q2", self.info(["Q11424"]), ["CYBERATTAQUE"], date(2026, 11, 6)))

    def test_nature_generique_prend_la_categorie_de_la_source(self):
        c = _candidat_wikipedia("Q3", self.info(["Q1190554"]), ["FUITE DE DONNÉES"], date(2026, 11, 6))
        self.assertEqual(c["categorie"], "FUITE DE DONNÉES")

    def test_avant_2005_ecarte(self):
        self.assertIsNone(_candidat_wikipedia("Q4", self.info(["Q4071928"], date="2003-01-25"), [],
                                              date(2026, 11, 6)))

    def test_dedoublonnage_cve_et_titre(self):
        wiki = [{"titre": "Log4Shell", "titre_en": "Log4Shell", "cves": ["CVE-2021-44228"]}]
        autres = [{"titre": "Apache Log4j2 RCE", "cves": ["CVE-2021-44228"]},
                  {"titre": "LOG4SHELL", "cves": []},
                  {"titre": "Autre faille", "cves": ["CVE-2020-1472"]}]
        self.assertEqual([c["titre"] for c in dedoublonner(wiki, autres)], ["Log4Shell", "Autre faille"])

    def test_normaliser(self):
        self.assertEqual(normaliser("L'attaque WannaCry (2017) — Été"), "l attaque wannacry 2017 ete")


if __name__ == "__main__":
    unittest.main()
