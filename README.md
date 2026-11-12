# TRACES — magazine quotidien de veille cybersécurité

Chaque matin, TRACES produit un numéro de 7 ou 8 pages A4 (HTML à feuilleter + PDF) à partir de
sources officielles et de presse : la faille du jour expliquée en cinq points, les failles
activement exploitées, un radar de brèves, une fiche Arnaques et une page d'histoire de la cyber.
Le magazine fonctionne **entièrement sans IA** ; chaque bloc porte une marque de provenance
(SOURCE, CALCULÉ, BIBLIOTHÈQUE) et garde le lien vers sa source.

Projet pédagogique d'un étudiant en M1 cybersécurité, pensé comme une branche d'un assistant
personnel modulaire. Les choix de conception sont détaillés dans [CLAUDE.md](CLAUDE.md).

## Sources

| Source | Usage |
|---|---|
| CERT-FR (ANSSI) | alertes, bulletins, export JSON officiel de chaque bulletin |
| CISA KEV | catalogue des failles activement exploitées |
| NVD (NIST) | score CVSS et type de faille (CWE) — dictionnaire uniquement |
| BleepingComputer, The Hacker News, Zataz, LeMagIT | brèves, dans leur langue d'origine |
| Wikipédia / Wikidata, MITRE ATT&CK | rubrique Histoire (événements de 2005 à aujourd'hui) |

## Installation (Windows)

```powershell
git clone <ce dépôt> traces
cd traces
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
copy .env.example .env     # puis remplir NVD_API_KEY et TRACES_CONTACT
```

- `NVD_API_KEY` : clé gratuite (https://nvd.nist.gov/developers/request-an-api-key). Sans clé, la
  NVD limite fortement les requêtes.
- `TRACES_CONTACT` : adresse de contact exigée par Wikimedia dans le User-Agent des robots
  (adresse dédiée au projet, pas un e-mail personnel). Sans elle, Wikipédia n'est pas interrogé.

Prérequis : Python 3.13, Microsoft Edge ou Google Chrome (pour le PDF ; aucune bibliothèque à installer).

## Utilisation

```powershell
.venv\Scripts\python.exe main.py              # numéro du jour -> sortie\traces_AAAA-MM-JJ.html + .pdf
.venv\Scripts\python.exe main.py --demo       # numéro de démonstration, sans Internet
.venv\Scripts\python.exe main.py --planning 7 # rubrique Histoire des 7 prochains jours (n'écrit rien)
.venv\Scripts\python.exe main.py --sans-pdf   # HTML seulement
.venv\Scripts\python.exe -m histoire.catalogue --forcer   # reconstruit le catalogue Histoire (rapport)
.venv\Scripts\python.exe -m unittest discover -s tests -t .   # tests (hors ligne)
```

### Lancement automatique chaque matin

```powershell
powershell -ExecutionPolicy Bypass -File .\outils\installer_tache.ps1      # crée la tâche « TRACES »
powershell -ExecutionPolicy Bypass -File .\outils\installer_tache.ps1 -Supprimer
```

La tâche réveille `outils\lancer_traces.ps1` toutes les 15 minutes à partir de 07:00 et à
l'ouverture de session ; le script génère le numéro dès que c'est possible (pas encore fait
aujourd'hui, Internet disponible), une seule fois par jour. Journal : `data\journal.log`.
Pour forcer une génération : `.\outils\lancer_traces.ps1 -Forcer`.

## Organisation du code

```
main.py            pipeline complet : collecte -> enrichissement -> sélection -> assemblage -> HTML -> PDF
config.py          tous les réglages (sources, seuils, chemins) ; les secrets sont dans .env
collecteurs/       un module par source, tous renvoient des Article
enrichissement/    bulletins CERT-FR, regroupement par CVE, NVD, CISA KEV
selection/         choix de la une, des failles exploitées, des brèves, de la fiche Arnaques
redaction/         rédacteur sans IA (textes officiels, vecteur CVSS traduit, glossaire CWE)
histoire/          catalogue des événements, choix du jour, mise en page, points de doute
bibliotheques/     contenus rédigés à l'avance : épisodes Histoire, fiches Arnaques, catalogue, mémoire
mise_en_page/      gabarits Jinja2, feuille de style, polices (incorporées), export PDF
outils/            contrôle A4 (deborde.ps1, hauteurs.ps1, rendus_histoire.py), lancement quotidien
tests/             tests unitaires, sans réseau
data/              caches et journal (créé au lancement, jamais commité)
sortie/            numéros générés (jamais commités)
```

## Principes de sécurité

- Le texte des sources est une **donnée, jamais une instruction** ; il est échappé avant d'entrer
  dans le HTML et seuls les liens `http(s)` sont conservés.
- Les clés sont dans `.env`, ignoré par Git.
- Les sites sont respectés : User-Agent explicite, pause entre les requêtes, caches, règles des
  robots d'API Wikimedia.
- Rien n'est inventé : un épisode d'histoire non relu est publié avec ses **points de doute**
  affichés en bas de page ; une fiche découverte ne contient que des extraits de sa source,
  attribués (Wikipédia, CC BY-SA 4.0).

## Licences

Code : projet personnel. Polices Archivo, Source Serif 4 et IBM Plex Mono : SIL Open Font License
(voir `mise_en_page/static/polices/LICENCES.txt`). Données MITRE ATT&CK : © The MITRE Corporation,
reproduites avec autorisation. Extraits Wikipédia : CC BY-SA 4.0.
