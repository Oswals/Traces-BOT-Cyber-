param([switch]$Supprimer)
# Crée (ou supprime) la tâche planifiée Windows « TRACES ».
# Principe : le numéro sort « dès que possible après 07:00, une fois par jour ». La tâche réveille
# outils\lancer_traces.ps1 toutes les 15 minutes de 07:00 à minuit et à chaque ouverture de session ;
# c'est le script qui vérifie s'il faut vraiment générer (pas encore fait aujourd'hui, Internet
# disponible). Un réveil pour rien dure moins d'une seconde et n'écrit rien.
# Usage : powershell -ExecutionPolicy Bypass -File .\outils\installer_tache.ps1
#         powershell -ExecutionPolicy Bypass -File .\outils\installer_tache.ps1 -Supprimer
$nom = "TRACES"
if ($Supprimer) {
    Unregister-ScheduledTask -TaskName $nom -Confirm:$false
    "Tâche $nom supprimée."
    exit 0
}
$script = Join-Path $PSScriptRoot "lancer_traces.ps1"
$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`""
$declencheurs = @(
    (New-ScheduledTaskTrigger -Daily -At "07:00"),
    (New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME)
)
# Répétition toutes les 15 min pendant 17 h (07:00 -> 00:00) sur le déclencheur quotidien
$declencheurs[0].Repetition = (New-ScheduledTaskTrigger -Once -At "07:00" -RepetitionInterval (New-TimeSpan -Minutes 15) -RepetitionDuration (New-TimeSpan -Hours 17)).Repetition
$reglages = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $nom -Action $action -Trigger $declencheurs -Settings $reglages -Description "Génère le numéro TRACES du jour (HTML + PDF) dès que possible après 07:00" -Force | Out-Null
"Tâche $nom installée : dès que possible après 07:00 chaque jour (vérification toutes les 15 min et à l'ouverture de session)."
"Journal : data\journal.log   Vérifier : schtasks /Query /TN $nom   Forcer maintenant : .\outils\lancer_traces.ps1 -Forcer"
