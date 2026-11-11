# Lance le numéro du jour et garde une trace dans data\journal.log.
# C'est ce script que le Planificateur de tâches Windows exécute chaque matin.
# Usage manuel : powershell -ExecutionPolicy Bypass -File .\outils\lancer_traces.ps1
$projet = Split-Path -Parent $PSScriptRoot
Set-Location $projet
$journal = Join-Path $projet "data\journal.log"
New-Item -ItemType Directory -Force (Join-Path $projet "data") | Out-Null

$debut = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Add-Content $journal "=== $debut : lancement" -Encoding utf8
# Sortie standard et erreurs vont ensemble dans le journal
& "$projet\.venv\Scripts\python.exe" main.py 2>&1 | ForEach-Object { "$_" } | Add-Content $journal -Encoding utf8
$code = $LASTEXITCODE
Add-Content $journal "=== fin, code $code" -Encoding utf8
exit $code
