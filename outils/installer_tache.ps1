param([string]$Heure = "07:00", [switch]$Supprimer)
# Crée (ou supprime) la tâche planifiée Windows « TRACES » qui génère le numéro chaque matin.
# Usage : powershell -ExecutionPolicy Bypass -File .\outils\installer_tache.ps1 [-Heure 07:30]
#         powershell -ExecutionPolicy Bypass -File .\outils\installer_tache.ps1 -Supprimer
# La tâche tourne avec ton compte, sans mot de passe à saisir, quand tu es connecté.
# Si le PC était éteint à l'heure prévue, elle part dès que possible (StartWhenAvailable).
$nom = "TRACES"
if ($Supprimer) {
    Unregister-ScheduledTask -TaskName $nom -Confirm:$false
    "Tâche $nom supprimée."
    exit 0
}
$script = Join-Path $PSScriptRoot "lancer_traces.ps1"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`""
$declencheur = New-ScheduledTaskTrigger -Daily -At $Heure
$reglages = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew
Register-ScheduledTask -TaskName $nom -Action $action -Trigger $declencheur -Settings $reglages -Description "Génère le numéro TRACES du jour (HTML + PDF)" -Force | Out-Null
"Tâche $nom installée : tous les jours à $Heure. Journal : data\journal.log"
"Vérifier : schtasks /Query /TN $nom    Lancer maintenant : schtasks /Run /TN $nom"
