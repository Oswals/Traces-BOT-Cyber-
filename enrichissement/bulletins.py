"""
Bulletins CERT-FR complets. Le flux RSS ne donne qu'un résumé ; chaque alerte et
chaque avis existe aussi en JSON officiel (adresse du bulletin + "json/"), avec
des sections séparées : systèmes affectés, risques, résumé, solution, CVE.

On range le résultat dans article.details["bulletin"] : le rédacteur n'a plus
qu'à lire, sans rien télécharger. Les réponses sont gardées dans
data/cache_certfr.json pour ne pas redemander chaque jour les mêmes bulletins.
"""

import json
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import config
from collecteurs.article import Article, nettoyer_html
from collecteurs.reseau import telecharger

log = logging.getLogger(__name__)

CATEGORIES = ("alerte", "avis")  # les bulletins d'actualité et la CTI n'ont pas ces sections


@dataclass
class Bulletin:
    reference: str                # ex. "CERTFR-2026-ALE-014"
    titre: str                    # ex. "Multiples vulnérabilités dans PHP"
    resume: str                   # texte brut
    systemes: list[str]           # ex. ["PHP versions 8.2.x antérieures à 8.2.35", ...]
    risques: list[str]            # ex. ["Exécution de code arbitraire à distance", ...]
    solution: str                 # section « Solutions », texte brut
    contournement: str            # section « Contournements provisoires » (souvent vide)
    cves: list[str] = field(default_factory=list)
    documentation: list[dict] = field(default_factory=list)  # bulletins des éditeurs : {"titre", "lien"}


def completer_bulletins(articles: list[Article], cves_connues: set[str]) -> None:
    """Ajoute le bulletin complet aux alertes et avis CERT-FR, et complète leur liste de CVE.

    Une alerte apporte toutes ses CVE. Un avis peut en lister une centaine (ex. les
    correctifs mensuels de Microsoft) : il n'apporte que les CVE déjà connues par
    ailleurs (exploitées selon la CISA, ou citées par une autre source). Sinon le
    numéro suivrait des centaines de failles et la NVD mettrait des heures à répondre.
    """
    a_lire = [a for a in articles if a.source == "CERT-FR" and a.details.get("categorie") in CATEGORIES]
    cache = _charger_cache()
    limite = datetime.now(timezone.utc) - timedelta(days=config.CERTFR_CACHE_JOURS)
    a_demander = [a for a in a_lire
                  if a.lien not in cache or datetime.fromisoformat(cache[a.lien]["date"]) < limite]
    if a_demander:
        log.info("[CERT-FR] %d bulletins JSON à télécharger, %d en cache (environ %d s)",
                 len(a_demander), len(a_lire) - len(a_demander), len(a_demander) * config.DELAI_REQUETES)
    try:
        for article in a_demander:
            brut = _telecharger_json(article.lien)
            if brut is not None:
                cache[article.lien] = {"date": datetime.now(timezone.utc).isoformat(), "json": brut}
    finally:
        _sauver_cache(cache)  # même en cas d'interruption, ce qui a été lu est gardé

    for article in a_lire:
        if article.lien not in cache:
            continue
        bulletin = lire_bulletin(cache[article.lien]["json"])
        article.details["bulletin"] = bulletin
        if article.details["categorie"] == "alerte":
            nouvelles = bulletin.cves
        else:
            nouvelles = [cve for cve in bulletin.cves if cve in cves_connues]
        article.cves = sorted(set(article.cves) | set(nouvelles))


def lire_bulletin(brut: dict) -> Bulletin:
    """Extrait les sections utiles du JSON officiel, en texte brut."""
    sections = _sections(brut.get("content", ""))
    return Bulletin(
        reference=brut.get("reference", ""),
        resume=texte_brut(brut.get("summary", "")),
        # Éléments de liste courts : nettoyés, mais sans ajout de point final
        systemes=[nettoyer_html(s.get("description", "")) for s in brut.get("affected_systems", [])
                  if s.get("description")],
        risques=[nettoyer_html(r.get("description", "")) for r in brut.get("risks", []) if r.get("description")],
        titre=nettoyer_html(brut.get("title", "")),
        solution=next((t for titre, t in sections.items() if titre.lower().startswith("solution")), ""),
        contournement=next((t for titre, t in sections.items() if titre.lower().startswith("contournement")), ""),
        cves=sorted({c.get("name", "") for c in brut.get("cves", []) if c.get("name")}),
        documentation=[{"titre": d.get("title", ""), "lien": d.get("url", "")}
                       for d in brut.get("vendor_advisories", []) if d.get("url")],
    )


def texte_brut(markdown: str) -> str:
    """Transforme le Markdown (et les quelques balises HTML) du CERT-FR en texte sur une ligne.

    Le Markdown est une façon d'écrire la mise en forme avec des symboles :
    **gras**, *italique*, « - » en début de ligne pour une liste, « ## » pour un titre.
    """
    texte = re.sub(r"<br\s*/?>", "\n", markdown, flags=re.IGNORECASE)
    texte = re.sub(r"<[^>]+>", "", texte)  # autres balises (<span>, <code>…) : on garde leur contenu
    texte = texte.replace("**", "").replace("__", "")
    texte = re.sub(r"(?<!\w)\*([^*\n]+)\*", r"\1", texte)  # *italique* -> italique

    lignes = []
    for ligne in texte.splitlines():
        ligne = re.sub(r"^\s*(?:[-*•]|\d+\.)\s+", "", ligne).strip()  # puces et numéros de liste
        if not ligne:
            continue
        if not ligne.endswith((".", ":", ";", "!", "?", "…")):
            ligne += "."  # une puce sans ponctuation devient une phrase
        lignes.append(ligne)
    return nettoyer_html(" ".join(lignes))  # retire les balises restantes et décode les &amp;


def _sections(contenu: str) -> dict[str, str]:
    """Découpe le contenu Markdown selon ses titres (« ## Solutions »)."""
    sections, titre, lignes = {}, None, []
    for ligne in contenu.splitlines():
        intertitre = re.match(r"^#{1,4}\s+(.+?)\s*$", ligne)
        if intertitre:
            if titre:
                sections[titre] = texte_brut("\n".join(lignes))
            titre, lignes = intertitre.group(1), []
        else:
            lignes.append(ligne)
    if titre:
        sections[titre] = texte_brut("\n".join(lignes))
    return sections


def _telecharger_json(lien: str) -> dict | None:
    url = lien.rstrip("/") + "/json/"
    contenu = telecharger(url)
    if contenu is None:
        return None
    try:
        return json.loads(contenu)
    except json.JSONDecodeError:
        log.warning("[CERT-FR] bulletin JSON illisible : %s", url)
        return None


def _charger_cache() -> dict:
    if not config.FICHIER_CACHE_CERTFR.exists():
        return {}
    try:
        return json.loads(config.FICHIER_CACHE_CERTFR.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        log.warning("%s est corrompu, on repart de zéro", config.FICHIER_CACHE_CERTFR.name)
        return {}


def _sauver_cache(cache: dict) -> None:
    config.FICHIER_CACHE_CERTFR.parent.mkdir(exist_ok=True)
    config.FICHIER_CACHE_CERTFR.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
