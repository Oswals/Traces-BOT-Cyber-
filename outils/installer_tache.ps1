param([switch]$Supprimer)
# Crée (ou supprime) la tâche planifiée Windows « TRACES ».
#
# Principe : le numéro sort « dès que possible après 07:00, une fois par jour ».
# La tâche réveille outils\lancer_traces.ps1 à chaque occasion où le PC redevient utilisable :
#   - tous les jours à 07:00, puis toutes les 15 min toute la journée ;
#   - à l'ouverture de session et au DÉVERROUILLAGE de session ;
#   - au réveil après une mise en veille ;
#   - quand le PC se connecte à un réseau (retour d'Internet).
# C'est le script qui décide s'il faut vraiment générer (après 07:00, pas encore fait aujourd'hui,
# Internet disponible). Un réveil pour rien dure moins d'une seconde et n'écrit rien.
#
# Pourquoi tous ces déclencheurs : sur un portable, Windows ne rattrape pas toujours un horaire
# manqué pendant la veille (constaté le 2026-11-12 : veille de 06:42 à 12:03, aucun lancement).
#
# Usage : powershell -ExecutionPolicy Bypass -File .\outils\installer_tache.ps1
#         powershell -ExecutionPolicy Bypass -File .\outils\installer_tache.ps1 -Supprimer
$nom = "TRACES"
if ($Supprimer) {
    Unregister-ScheduledTask -TaskName $nom -Confirm:$false
    "Tâche $nom supprimée."
    exit 0
}

$utilisateur = "$env:USERDOMAIN\$env:USERNAME"
$script = Join-Path $PSScriptRoot "lancer_traces.ps1"
$aujourdhui = (Get-Date).ToString("yyyy-MM-dd")
# conhost --headless lance PowerShell sans aucune fenêtre (pas de flash noir au déverrouillage)
$arguments = "--headless powershell.exe -NoProfile -ExecutionPolicy Bypass -File &quot;$script&quot;"

# Une tâche planifiée se décrit en XML : c'est le seul moyen d'y mettre des déclencheurs
# « sur événement » (réveil, réseau) depuis PowerShell.
$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Génère le numéro TRACES du jour (HTML + PDF) dès que possible après 07:00</Description>
    <URI>\$nom</URI>
  </RegistrationInfo>
  <Triggers>
    <CalendarTrigger>
      <StartBoundary>${aujourdhui}T07:00:00</StartBoundary>
      <Repetition><Interval>PT15M</Interval><Duration>P1D</Duration><StopAtDurationEnd>false</StopAtDurationEnd></Repetition>
      <ScheduleByDay><DaysInterval>1</DaysInterval></ScheduleByDay>
    </CalendarTrigger>
    <LogonTrigger><UserId>$utilisateur</UserId><Delay>PT1M</Delay></LogonTrigger>
    <SessionStateChangeTrigger><StateChange>SessionUnlock</StateChange><UserId>$utilisateur</UserId><Delay>PT1M</Delay></SessionStateChangeTrigger>
    <EventTrigger>
      <Delay>PT1M</Delay>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="System"&gt;&lt;Select Path="System"&gt;*[System[Provider[@Name='Microsoft-Windows-Power-Troubleshooter'] and EventID=1]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
    <EventTrigger>
      <Delay>PT1M</Delay>
      <Subscription>&lt;QueryList&gt;&lt;Query Id="0" Path="Microsoft-Windows-NetworkProfile/Operational"&gt;&lt;Select Path="Microsoft-Windows-NetworkProfile/Operational"&gt;*[System[EventID=10000]]&lt;/Select&gt;&lt;/Query&gt;&lt;/QueryList&gt;</Subscription>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Auteur">
      <UserId>$utilisateur</UserId>
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT30M</ExecutionTimeLimit>
    <Enabled>true</Enabled>
  </Settings>
  <Actions Context="Auteur">
    <Exec>
      <Command>conhost.exe</Command>
      <Arguments>$arguments</Arguments>
    </Exec>
  </Actions>
</Task>
"@

Register-ScheduledTask -TaskName $nom -Xml $xml -Force | Out-Null
"Tâche $nom installée : dès que possible après 07:00, une fois par jour."
"Déclencheurs : 07:00 puis toutes les 15 min, ouverture et déverrouillage de session, réveil de veille, connexion réseau."
"Journal : data\journal.log   Forcer maintenant : .\outils\lancer_traces.ps1 -Forcer"
