# Lance le numéro du jour si les conditions sont réunies, et garde une trace dans data\journal.log.
# Le Planificateur de tâches appelle ce script souvent (toutes les 15 min à partir de 07:00, et à
# l'ouverture de session) : il décide lui-même s'il y a quelque chose à faire.
#   - il est au moins 07:00 ;
#   - le numéro du jour n'existe pas encore (sortie\traces_AAAA-MM-JJ.html) ;
#   - Internet répond (le CERT-FR est joignable) ;
#   - moins de 4 tentatives ratées aujourd'hui (sinon on attend demain, pour ne pas boucler).
# Rien n'est écrit dans le journal quand il n'y a rien à faire.
# Usage manuel : powershell -ExecutionPolicy Bypass -File .\outils\lancer_traces.ps1 [-Forcer]
param([switch]$Forcer)

$projet = Split-Path -Parent $PSScriptRoot
Set-Location $projet
$donnees = Join-Path $projet "data"
New-Item -ItemType Directory -Force $donnees | Out-Null
$journal = Join-Path $donnees "journal.log"
$jour = Get-Date -Format "yyyy-MM-dd"
$numero = Join-Path $projet "sortie\traces_$jour.html"
$tentatives = Join-Path $donnees "tentatives_$jour.txt"
$HEURE_MIN = 7
$ESSAIS_MAX = 4

if (-not $Forcer) {
    if ((Get-Date).Hour -lt $HEURE_MIN) { exit 0 }
    if (Test-Path $numero) { exit 0 }
    $essais = 0
    if (Test-Path $tentatives) { $essais = [int](Get-Content $tentatives) }
    if ($essais -ge $ESSAIS_MAX) { exit 0 }
    $connecte = $false
    try { $connecte = Test-NetConnection -ComputerName "cert.cyber.gouv.fr" -Port 443 -InformationLevel Quiet -WarningAction SilentlyContinue } catch {}
    if (-not $connecte) { exit 0 }
}

$debut = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Add-Content $journal "=== $debut : lancement" -Encoding utf8
& "$projet\.venv\Scripts\python.exe" main.py 2>&1 | ForEach-Object { "$_" } | Add-Content $journal -Encoding utf8
$code = $LASTEXITCODE
Add-Content $journal "=== fin, code $code" -Encoding utf8
if ($code -ne 0) {
    $essais = 0
    if (Test-Path $tentatives) { $essais = [int](Get-Content $tentatives) }
    Set-Content $tentatives ($essais + 1)
    if ($essais + 1 -ge $ESSAIS_MAX) { Add-Content $journal "=== $ESSAIS_MAX échecs aujourd'hui : on réessaiera demain" -Encoding utf8 }
}
# Ménage : les compteurs des jours précédents
Get-ChildItem (Join-Path $donnees "tentatives_*.txt") | Where-Object { $_.Name -ne "tentatives_$jour.txt" } | Remove-Item -Force
exit $code
