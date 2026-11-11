param([string]$Fichier)
# Mesure, pour chaque page A4 d'un numéro, de combien de pixels le contenu dépasse (0 = tient).
# Ouvre le fichier dans Edge sans fenêtre, attend les polices, puis lit scrollHeight - clientHeight.
# Usage : .\outils\deborde.ps1 -Fichier .\sortie\traces_demo.html
$edge = Get-ChildItem "C:\Program Files\Microsoft\Edge\Application\msedge.exe", "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
if (-not $edge) { Write-Error "Edge introuvable"; exit 1 }
$copie = "$env:TEMP\traces_mesure.html"
$out = "$env:TEMP\traces_dom_check.html"
$mesure = '<script>document.fonts.ready.then(()=>{for(const c of document.querySelectorAll(".page-contenu")){c.parentElement.dataset.depasse=c.scrollHeight-c.clientHeight;}});</script></body>'
$html = [IO.File]::ReadAllText((Resolve-Path $Fichier)).Replace('</body>', $mesure)
[IO.File]::WriteAllText($copie, $html)
$url = '"file:///' + $copie.Replace('\', '/').Replace(' ', '%20') + '"'
Start-Process -FilePath $edge -ArgumentList "--headless=new", "--disable-gpu", "--window-size=1400,1200", "--user-data-dir=$env:TEMP\edge_traces", "--virtual-time-budget=8000", "--dump-dom", $url -RedirectStandardOutput $out -RedirectStandardError "$env:TEMP\edge_err.txt" -Wait -NoNewWindow
Select-String -Path $out -Pattern 'id="([^"]*)" data-depasse="(-?\d+)"' -AllMatches | ForEach-Object { $_.Matches | ForEach-Object { "{0,-16} {1,6} px" -f $_.Groups[1].Value, $_.Groups[2].Value } }
