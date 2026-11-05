"""
Numéro de DÉMONSTRATION, entièrement fictif (éditeurs « Acme », « Globex »...,
CVE en 2099). Il sert à voir le magazine avant de brancher les vraies données,
et il fixe la structure exacte que l'étape 5 devra remplir.

Valeurs possibles :
  provenance : "source", "calcule", "bibliotheque", "ia_locale"
  niveau     : "faible", "moyenne", "haute", "critique" (niveau de menace CVSS)
"""

import json

from config import DOSSIER_ARNAQUES

LIEN_DEMO = "https://example.org/"  # domaine réservé aux exemples, ne mène nulle part

NUMERO = {
    "demo": True,
    "numero": 1,
    "date": "3 novembre 2026",

    # --- Page 2 : « Le numéro en bref » (chiffres calculés) ---------------------
    "bref": {"failles": 37, "critiques": 14, "exploitees": 32, "sources": 7, "articles": 167},

    # --- Pages 1 et 3 : la une ---------------------------------------------------
    "une": {
        "titre": "Acme SecureGate : une faille critique déjà exploitée",
        "titre_officiel": "Multiples vulnérabilités dans Acme SecureGate (CERTFR-2099-ALE-001)",
        "cve": "CVE-2099-0001",
        "produit": "Acme SecureGate",
        "score": 9.8,
        "niveau": "critique",
        "exploitee": True,
        "resume": {
            "texte": "Une vulnérabilité a été découverte dans Acme SecureGate. Elle permet à un "
                     "attaquant non authentifié d'exécuter du code arbitraire à distance. L'éditeur "
                     "indique qu'elle est activement exploitée.",
            "provenance": "source", "source": "CERT-FR", "lien": LIEN_DEMO,
        },
        # Le score et l'exploitation sont déjà affichés en pastilles : pas de doublon ici
        "fiche": [
            ("CVE", "CVE-2099-0001"),
            ("Produit", "Acme SecureGate 7.x avant 7.4.2"),
            ("Type de faille", "CWE-78 · Injection de commande"),
            ("Exploitée depuis", "30/10/2026 (CISA KEV)"),
            ("Publication", "CERT-FR · 3 novembre 2026"),
        ],
        # 8 cases traduites du vecteur CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        "profil": [
            {"critere": "Accès", "valeur": "Par Internet", "niveau": "critique"},
            {"critere": "Difficulté", "valeur": "Faible", "niveau": "critique"},
            {"critere": "Compte nécessaire", "valeur": "Aucun", "niveau": "critique"},
            {"critere": "Action de la victime", "valeur": "Aucune", "niveau": "critique"},
            {"critere": "Portée", "valeur": "Limitée au produit", "niveau": "moyenne"},
            {"critere": "Confidentialité", "valeur": "Perte totale", "niveau": "haute"},
            {"critere": "Intégrité", "valeur": "Perte totale", "niveau": "haute"},
            {"critere": "Disponibilité", "valeur": "Perte totale", "niveau": "haute"},
        ],
        "comprendre": [
            {"question": "C'est quoi ?", "provenance": "bibliotheque", "source": "Glossaire CWE-78",
             "texte": "Une injection de commande : le programme construit une commande système à "
                      "partir d'un texte envoyé par l'utilisateur, sans le filtrer. L'attaquant y glisse "
                      "ses propres commandes, que le serveur exécute."},
            {"question": "Qui est touché ?", "provenance": "source", "source": "CERT-FR",
             "texte": "Acme SecureGate versions 7.0 à 7.4.1, et Acme SecureGate Cloud avant le "
                      "28 octobre 2026."},
            {"question": "Gravité", "provenance": "calcule", "source": "Vecteur CVSS 3.1 (NVD)",
             "texte": "9,8 sur 10 : exploitable par Internet, sans compte ni action de la victime, "
                      "avec une perte totale de confidentialité, d'intégrité et de disponibilité."},
            {"question": "Que peut faire un attaquant ?", "provenance": "source", "source": "CERT-FR",
             "texte": "Exécution de code arbitraire à distance. Atteinte à la confidentialité des données."},
            {"question": "Comment se protéger ?", "provenance": "source", "source": "CERT-FR",
             "texte": "Appliquer la version 7.4.2. En attendant, restreindre l'accès à l'interface "
                      "d'administration et rechercher des traces de compromission."},
        ],
        "lien": LIEN_DEMO,
    },

    # --- Page 4 : 3 failles exploitées -----------------------------------------
    "failles": [
        {"cve": "CVE-2099-0002", "produit": "Globex FileShare", "score": 9.1, "niveau": "critique",
         "titre": "Globex FileShare : contournement de l'authentification",
         "exploitee": True, "en_anglais": True, "lien": LIEN_DEMO,
         "points": [
             {"question": "C'est quoi ?", "provenance": "bibliotheque", "source": "Glossaire CWE-287",
              "texte": "Une authentification défaillante : le serveur croit que l'utilisateur s'est "
                       "identifié alors qu'il ne l'a pas fait."},
             {"question": "Qui est touché ?", "provenance": "source", "source": "NVD",
              "texte": "Globex FileShare 3.0 à 3.2."},
             {"question": "Gravité", "provenance": "calcule", "source": "CVSS 3.1",
              "texte": "9,1 sur 10 : par Internet, sans compte."},
             {"question": "Que peut faire un attaquant ?", "provenance": "source", "source": "CISA (EN)",
              "texte": "Globex FileShare contains an improper authentication vulnerability that "
                       "allows an attacker to access files without credentials."},
             {"question": "Comment se protéger ?", "provenance": "source", "source": "CISA (EN)",
              "texte": "Apply mitigations per vendor instructions or discontinue use of the product."},
         ]},
        {"cve": "CVE-2099-0003", "produit": "Initech Mail Server", "score": 8.1, "niveau": "haute",
         "titre": "Initech Mail Server : exécution de code par un courriel piégé",
         "exploitee": True, "en_anglais": False, "lien": LIEN_DEMO,
         "points": [
             {"question": "C'est quoi ?", "provenance": "bibliotheque", "source": "Glossaire CWE-787",
              "texte": "Une écriture hors limites : le programme écrit en mémoire au-delà de la zone "
                       "prévue, ce qui peut détourner son fonctionnement."},
             {"question": "Qui est touché ?", "provenance": "source", "source": "CERT-FR",
              "texte": "Initech Mail Server versions antérieures à 12.0.3."},
             {"question": "Gravité", "provenance": "calcule", "source": "CVSS 3.1",
              "texte": "8,1 sur 10 : par Internet, mais difficile à exploiter."},
             {"question": "Que peut faire un attaquant ?", "provenance": "source", "source": "CERT-FR",
              "texte": "Exécution de code arbitraire à distance."},
             {"question": "Comment se protéger ?", "provenance": "source", "source": "CERT-FR",
              "texte": "Appliquer la version 12.0.3 publiée par l'éditeur."},
         ]},
        {"cve": "CVE-2099-0004", "produit": "Umbrella RouterOS", "score": 7.5, "niveau": "haute",
         "titre": "Umbrella RouterOS : déni de service à distance",
         "exploitee": True, "en_anglais": True, "lien": LIEN_DEMO,
         "points": [
             {"question": "C'est quoi ?", "provenance": "bibliotheque", "source": "Glossaire CWE-400",
              "texte": "Une consommation de ressources non maîtrisée : quelques requêtes suffisent à "
                       "épuiser la mémoire ou le processeur de l'appareil."},
             {"question": "Qui est touché ?", "provenance": "source", "source": "CISA (EN)",
              "texte": "Umbrella RouterOS."},
             {"question": "Gravité", "provenance": "calcule", "source": "CVSS 3.1",
              "texte": "7,5 sur 10 : par Internet, sans compte, atteinte à la disponibilité seulement."},
             {"question": "Que peut faire un attaquant ?", "provenance": "source", "source": "CISA (EN)",
              "texte": "Umbrella RouterOS contains an uncontrolled resource consumption vulnerability "
                       "that allows a remote attacker to cause a denial of service."},
             {"question": "Comment se protéger ?", "provenance": "source", "source": "CISA (EN)",
              "texte": "Apply mitigations per vendor instructions."},
         ]},
    ],

    # --- Page 5 : radar -----------------------------------------------------------
    "radar": {
        "gravite": [
            {"niveau": "critique", "nombre": 14},
            {"niveau": "haute", "nombre": 12},
            {"niveau": "moyenne", "nombre": 8},
            {"niveau": "faible", "nombre": 2},
        ],
        "sans_score": 1,
        "provenance": [
            {"source": "CERT-FR", "nombre": 49}, {"source": "The Hacker News", "nombre": 50},
            {"source": "CISA KEV", "nombre": 32}, {"source": "BleepingComputer", "nombre": 15},
            {"source": "Zataz", "nombre": 10}, {"source": "LeMagIT", "nombre": 8},
        ],
        "breves_monde": [
            {"titre": "Acme warns of a new phishing wave targeting SecureGate admins",
             "resume": "Attackers send fake update notices to administrators to steal their credentials.",
             "source": "BleepingComputer", "langue": "en", "lien": LIEN_DEMO},
            {"titre": "Globex patches FileShare flaw after mass exploitation",
             "resume": "Thousands of exposed servers were compromised before the patch was available.",
             "source": "The Hacker News", "langue": "en", "lien": LIEN_DEMO},
            {"titre": "Ransomware group claims attack on fictional logistics firm",
             "resume": "The group published sample files on its leak site and set a ten-day deadline.",
             "source": "BleepingComputer", "langue": "en", "lien": LIEN_DEMO},
        ],
        "breves_france": [
            {"titre": "Une collectivité fictive victime d'un rançongiciel",
             "resume": "Les services en ligne sont coupés depuis lundi, une plainte a été déposée.",
             "source": "Zataz", "langue": "fr", "lien": LIEN_DEMO},
            {"titre": "Un SOC mutualisé pour les hôpitaux d'une région fictive",
             "resume": "Le projet vise à surveiller en continu les établissements les plus petits.",
             "source": "LeMagIT", "langue": "fr", "lien": LIEN_DEMO},
        ],
    },

    # --- Page 6 : arnaques (alerte fictive + vraie fiche de la bibliothèque) -------------
    "arnaque": {
        "mode": "presse",
        "rubrique": "L'arnaque du moment",
        "alerte": {"titre": "Faux concours sur une messagerie : une vague de vols de comptes",
                   "resume": "Des messages envoyés par des proches piratés invitent à voter pour un "
                             "concours. Le site demande le numéro de téléphone puis le code reçu par SMS.",
                   "source": "Zataz", "langue": "fr", "lien": LIEN_DEMO, "date": "2 novembre 2026"},
        "fiche": json.loads((DOSSIER_ARNAQUES / "vol-compte-messagerie.json").read_text(encoding="utf-8")),
        "lien_cybermalveillance": "https://www.cybermalveillance.gouv.fr/",
    },

    # --- Pages 6 et 7 : l'histoire (bibliothèque vérifiée, étape 7) ---------------
    "histoire": {
        "titre": "Titre de l'épisode",
        "annee": "2017",
        "chapeau": "Épisode de démonstration. Les vrais épisodes seront rédigés à l'avance, "
                   "vérifiés et sourcés à l'étape 7 (le premier : WannaCry).",
        "sections_p1": [
            {"titre": "Contexte", "texte": "Ici, le décor : quelle organisation, quel pays, quelle "
             "époque, et pourquoi la cible était exposée. Deux ou trois paragraphes courts, "
             "compréhensibles sans connaissances préalables."},
            {"titre": "Déroulement", "texte": "Ici, le récit des faits dans l'ordre : la première "
             "intrusion, la propagation, la découverte par les défenseurs, puis la réaction. "
             "Chaque fait important renvoie à une source listée en fin d'épisode."},
            {"titre": "La faille", "texte": "Ici, l'explication technique de la faille ou de la "
             "technique utilisée, avec sa CVE si elle existe, et le lien avec le glossaire CWE."},
        ],
        "sections_p2": [
            {"titre": "Victimes", "texte": "Ici, qui a été touché, combien, dans quels secteurs."},
            {"titre": "Conséquences", "texte": "Ici, le coût, les services interrompus, les suites "
             "judiciaires et réglementaires."},
            {"titre": "Enseignements", "texte": "Ici, ce que l'événement a changé et les bonnes "
             "pratiques qui en découlent : ce qu'il faut retenir pour un cours ou un entretien."},
        ],
        "chronologie": [
            {"date": "Mars", "evenement": "Publication du correctif par l'éditeur."},
            {"date": "Avril", "evenement": "Divulgation publique de l'outil d'exploitation."},
            {"date": "12 mai", "evenement": "Début de l'attaque, propagation mondiale."},
            {"date": "13 mai", "evenement": "Découverte d'un moyen d'arrêter la propagation."},
            {"date": "Décembre", "evenement": "Attribution officielle par plusieurs États."},
        ],
        "schema": [
            {"etape": "Entrée", "detail": "Port réseau exposé"},
            {"etape": "Exploitation", "detail": "Faille du service"},
            {"etape": "Installation", "detail": "Dépôt du programme"},
            {"etape": "Propagation", "detail": "Recherche d'autres machines"},
            {"etape": "Impact", "detail": "Chiffrement et rançon"},
        ],
        "lexique": [
            {"terme": "Ver", "definition": "Programme malveillant qui se propage seul d'une machine à l'autre."},
            {"terme": "Correctif", "definition": "Mise à jour qui supprime une faille."},
        ],
        "sources": [
            {"titre": "Source officielle 1 (exemple)", "lien": LIEN_DEMO},
            {"titre": "Source officielle 2 (exemple)", "lien": LIEN_DEMO},
        ],
    },

    # --- Lexique de la une (termes présents dans le numéro) ----------------------
    "lexique": [
        {"terme": "CVE", "definition": "Identifiant unique d'une faille publique (Common Vulnerabilities and Exposures)."},
        {"terme": "CVSS", "definition": "Note de gravité d'une faille, de 0 à 10."},
        {"terme": "Exécution de code à distance", "definition": "L'attaquant fait exécuter ses propres instructions par la machine visée, sans y avoir accès physiquement."},
    ],
}
