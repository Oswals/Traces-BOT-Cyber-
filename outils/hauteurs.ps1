param([string]$Fichier, [string]$Page = "failles")
# Hauteur en pixels de chaque bloc d'une page, pour trouver ce qui fait déborder.
# Usage : .\outils\hauteurs.ps1 -Fichier .\sortie\traces_demo.html -Page histoire-suite
$edge = Get-ChildItem "C:\Program Files\Microsoft\Edge\Application\msedge.exe", "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty FullName
if (-not $edge) { Write-Error "Edge introuvable"; exit 1 }
$copie = "$env:TEMP\traces_hauteurs.html"
$out = "$env:TEMP\traces_dom_h.html"
$js = @"
<script>document.fonts.ready.then(()=>{const r=[];const p=document.getElementById('$Page');
const c=p.querySelector('.page-contenu');const enfants=[...c.children];
const bas=Math.max(...enfants.map(e=>e.getBoundingClientRect().bottom+parseFloat(getComputedStyle(e).marginBottom)));
const utilise=Math.round(bas-c.getBoundingClientRect().top);
r.push('utilise '+utilise+' / disponible '+c.clientHeight+' / marge '+(c.clientHeight-utilise));
r.push('polices '+[...document.fonts].filter(f=>f.status==='loaded').length);
for(const el of p.querySelectorAll('.page-contenu > *, .fiche-faille-tete, .point, .une-titres, .profil, .comprendre, .identite, .lexique, .doutes')){r.push(el.className+' '+Math.round(el.getBoundingClientRect().height));}
const d=document.createElement('pre');d.id='mesures';d.textContent=r.join('|');document.body.appendChild(d);});</script></body>
"@
$html = [IO.File]::ReadAllText((Resolve-Path $Fichier)).Replace('</body>', $js)
[IO.File]::WriteAllText($copie, $html)
$url = '"file:///' + $copie.Replace('\', '/').Replace(' ', '%20') + '"'
Start-Process -FilePath $edge -ArgumentList "--headless=new", "--disable-gpu", "--window-size=1400,1200", "--user-data-dir=$env:TEMP\edge_traces", "--virtual-time-budget=8000", "--dump-dom", $url -RedirectStandardOutput $out -RedirectStandardError "$env:TEMP\edge_err.txt" -Wait -NoNewWindow
$m = Select-String -Path $out -Pattern '<pre id="mesures">(.*?)</pre>' | ForEach-Object { $_.Matches[0].Groups[1].Value }
$m -split '\|'
