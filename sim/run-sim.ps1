# run-sim.ps1 -- PC-side driver for the fake-Stadia-controller integration gate.
# ASCII only (PLAYBOOK: a .ps1 must never contain non-ASCII, PS 5.1 decodes it as GBK).
#
#   .\run-sim.ps1                      # join StadiaPhone, run T1, rejoin home WiFi
#   .\run-sim.ps1 -Tier T1T2           # T1 + DTLS probe (T2)
#   .\run-sim.ps1 -SkipWifi            # phone already on the AP
#   .\run-sim.ps1 -PadRegister 6156    # reproduce the real-machine 6156 B request
#
# Everything leaves the phone: the only PC-side network use is none at all. The
# phone joins the Pico AP, speaks TLS/UDP to 192.168.137.1, and the PC only pushes
# payloads, pulls results and judges them.
[CmdletBinding()]
param(
  [string]$Serial = '',
  [string]$AdbExe = 'adb',
  [string]$Ssid = 'StadiaPhone',
  [string]$Pass = 'TestPass1234a',
  [string]$HomeSsid = '',
  [string]$Tier = 'T1',
  [switch]$SkipWifi,
  [switch]$KeepOnAp,
  [int]$PadRegister = 0
)

$ErrorActionPreference = 'Continue'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$payload = Join-Path $here 'payload'
$outDir = Join-Path $here 'out'
$phoneDir = '/data/local/tmp/simctrl'

$node = 'node'
if (-not (Get-Command $node -ErrorAction SilentlyContinue)) { $node = $null }
if (-not $node) { Write-Host '[FATAL] node.exe not found on PATH (need Node.js 18+)'; exit 9 }
if (-not $Serial) { Write-Host '[FATAL] pass -Serial <adb-serial> (see README)'; exit 9 }
if (-not $KeepOnAp -and -not $HomeSsid -and -not $SkipWifi) { Write-Host '[FATAL] pass -HomeSsid <ssid> so the phone can be restored, or -KeepOnAp'; exit 9 }

function Sh([string]$c) {
  $r = & $AdbExe -s $Serial shell $c 2>&1 | Out-String
  return $r.Trim()
}
function RSh([string]$c) {
  $r = & $AdbExe -s $Serial shell "su -c '$c'" 2>&1 | Out-String
  return $r.Trim()
}
function Step([string]$s) { Write-Host ("[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $s) }

# ---- 0. device ------------------------------------------------------------
Step "device check ($Serial)"
$dev = (& $AdbExe devices 2>&1 | Out-String)
if ($dev -notmatch ([regex]::Escape($Serial) + '\s+device')) {
  Write-Host '[FATAL] adb device not present:'; Write-Host $dev; exit 9
}
$stateBefore = Sh 'cmd wifi status'
$homeBefore = ([regex]::Match($stateBefore, 'connected to "([^"]+)"')).Groups[1].Value
$ipBefore = ([regex]::Match($stateBefore, 'IP: /([0-9.]+)')).Groups[1].Value
Step ("before: ssid={0} ip={1}" -f $homeBefore, $ipBefore)

$gate = $null
$pdnSaved = $null
try {
  # ---- 1. join the Pico AP ------------------------------------------------
  # Private DNS (DoT) is unreachable on the Pico AP: the resolution failures make
  # Android call the network "no internet" and it hops back to the home SSID
  # mid-test (verified: stable >36 s with private DNS off, flaps within ~25 s on).
  $pdnSaved = RSh 'settings get global private_dns_mode'
  if ($pdnSaved -ne 'off') {
    Step "private DNS was '$pdnSaved' -> off for the run"
    RSh 'settings put global private_dns_mode off' | Out-Null
  }
  # No mobile-data escape hatch either: with the Pico AP unvalidated, Android will
  # otherwise treat mobile data as the better network and hop off mid-run.
  $dataSaved = RSh 'settings get global mobile_data'
  if ($dataSaved -ne '0') {
    Step "mobile data was '$dataSaved' -> off for the run"
    RSh 'svc data disable' | Out-Null
  }
  RSh 'settings put global network_avoid_bad_wifi 0' | Out-Null
  if (-not $SkipWifi) {
    $joined = $false
    for ($try = 1; $try -le 3 -and -not $joined; $try++) {
      Step "joining $Ssid (attempt $try)"
      $r = RSh "cmd wifi connect-network $Ssid wpa2 $Pass"
      if ($r) { Write-Host "      $r" }
      for ($i = 0; $i -lt 24; $i++) {
        Start-Sleep -Seconds 1
        if ((Sh 'ip -4 addr show wlan0') -match 'inet 192\.168\.137\.') { $joined = $true; break }
      }
      if (-not $joined) {
        Step 'no lease yet - wifi toggle and retry'
        RSh 'svc wifi disable' | Out-Null
        Start-Sleep -Seconds 2
        RSh 'svc wifi enable' | Out-Null
        Start-Sleep -Seconds 5
      }
    }
  }
  $ip = $null
  $deadline = (Get-Date).AddSeconds(50)
  while ((Get-Date) -lt $deadline) {
    $m = [regex]::Match((Sh 'ip -4 addr show wlan0'), 'inet (192\.168\.137\.\d+)')
    if ($m.Success) { $ip = $m.Groups[1].Value; break }
    Start-Sleep -Seconds 1
  }
  if (-not $ip) {
    Step 'FAIL: no 192.168.137.x lease on wlan0 after 50s'
    Write-Host (Sh 'cmd wifi status')
    exit 3
  }
  Step "online on AP: $ip"

  $ping = Sh 'ping -c 3 -W 2 192.168.137.1'
  $recv = ([regex]::Match($ping, '(\d+) received')).Groups[1].Value
  Step "ping 192.168.137.1 received=$recv/3"

  # ---- 1b. preflight: is the Pico's IP stack alive at all? -----------------
  # Observed failure mode (2026-11-08): the CYW43 keeps beaconing/associating while
  # the RP2350 network stack stops answering ARP/DNS/TCP/UDP; every request then
  # times out and the gate would report 16 meaningless FAILs. ARP is the cheapest
  # proof that the host side is processing frames.
  Sh 'ip neigh flush dev wlan0' | Out-Null
  Sh 'ping -c 2 -W 2 192.168.137.1' | Out-Null
  Start-Sleep -Seconds 1
  $arp = Sh 'ip neigh show dev wlan0'
  if ($arp -match '192\.168\.137\.1') {
    Step "preflight: ARP ok ($arp)"
  } else {
    Step 'preflight: NO ARP REPLY from 192.168.137.1'
    Step 'BLOCKED: Pico AP is up but its IP stack is unresponsive (firmware wedge).'
    Step 'Evidence: ip neigh empty, DNS 53 / UDP 40000 / TCP 443 all silent, association held.'
    Step 'Action: power-cycle the Pico once (owner action), then re-run this script.'
    exit 4
  }
  Start-Sleep -Seconds 2

  # ---- 2. payloads --------------------------------------------------------
  Step "building request bodies (candidate=$ip:41000 pad=$PadRegister)"
  & $node (Join-Path $here 'sim\make-bodies.cjs') --ip $ip --port 41000 --out $payload --pad-register $PadRegister
  if ($LASTEXITCODE -ne 0) { Write-Host '[FATAL] make-bodies failed'; exit 9 }

  # ---- 3. push + run ------------------------------------------------------
  Sh "rm -rf $phoneDir; mkdir -p $phoneDir/out" | Out-Null
  & $AdbExe -s $Serial push (Join-Path $payload '.') "$phoneDir/" 2>&1 | Out-Null
  & $AdbExe -s $Serial push (Join-Path $here 'sim\t1.sh') "$phoneDir/t1.sh" 2>&1 | Out-Null
  Step 'running T1 on the phone (curl + BoringSSL, all packets from wlan0)'
  $t0 = Get-Date
  $t1out = Sh "sh $phoneDir/t1.sh"
  $elapsed = [int]((Get-Date) - $t0).TotalSeconds
  Write-Host "      t1.sh finished in ${elapsed}s"
  if ($t1out -notmatch 'T1_DONE') { Write-Host '[WARN] t1.sh did not print T1_DONE:'; Write-Host $t1out }

  # ---- 4. pull + judge ----------------------------------------------------
  if (Test-Path $outDir) { Remove-Item -Recurse -Force $outDir }
  & $AdbExe -s $Serial pull "$phoneDir/out" $outDir 2>&1 | Out-Null
  if (-not (Test-Path (Join-Path $outDir 't1.log'))) {
    Write-Host '[FATAL] no t1.log pulled'; exit 3
  }
  & $node (Join-Path $here 'sim\verify.cjs') --out $outDir
  $t1code = $LASTEXITCODE
  $gate = @{ T1 = ($t1code -eq 0) }

  # ---- 5. T2 (DTLS over the phone's UDP socket) ---------------------------
  if ($Tier -match 'T2|T3') {
    Step 'running T2 (DTLS handshake probe to 192.168.137.1:40000)'
    & $node (Join-Path $here 'sim\dtls-probe.cjs') --serial $Serial --adb $AdbExe --out $outDir
    $gate.T2 = ($LASTEXITCODE -eq 0)
  }
}
finally {
  if ($pdnSaved -and $pdnSaved -ne 'off') { RSh "settings put global private_dns_mode $pdnSaved" | Out-Null }
  if ($dataSaved -and $dataSaved -ne '0') { RSh 'svc data enable' | Out-Null }
  if (-not $KeepOnAp) {
    Step "restoring home WiFi ($HomeSsid)"
    $nets = RSh 'cmd wifi list-networks'
    $id = $null
    foreach ($line in ($nets -split "`n")) {
      if ($line -match '^\s*(\d+)\s+' + [regex]::Escape($Ssid) + '\s') { $id = $Matches[1]; break }
    }
    if ($id) { Write-Host ("      forgetting {0} (netid {1})" -f $Ssid, $id); RSh "cmd wifi forget-network $id" | Out-Null }
    RSh 'svc wifi disable' | Out-Null
    Start-Sleep -Seconds 2
    RSh 'svc wifi enable' | Out-Null
    $back = $false
    for ($i = 0; $i -lt 40; $i++) {
      Start-Sleep -Seconds 1
      if ((Sh 'cmd wifi status') -match ('connected to "' + [regex]::Escape($HomeSsid) + '"')) { $back = $true; break }
    }
    if ($back) {
      $ipNow = ([regex]::Match((Sh 'ip -4 addr show wlan0'), 'inet ([0-9.]+)')).Groups[1].Value
      Step "home WiFi restored: $HomeSsid ($ipNow)"
    } else {
      Step "WARN: could not rejoin $HomeSsid - phone may be offline"
      Write-Host (Sh 'cmd wifi status')
    }
  }
}

Write-Host ''
if ($gate) {
  $all = -not ($gate.Values -contains $false)
  foreach ($k in $gate.Keys) { Write-Host ("GATE {0} {1}" -f $k, $(if ($gate[$k]) { 'PASS' } else { 'FAIL' })) }
  Write-Host ("GATE ALL {0}" -f $(if ($all) { 'PASS' } else { 'FAIL' }))
  if (-not $all) { exit 2 }
} else {
  Write-Host 'GATE ALL FAIL (no verdict produced)'
  exit 2
}
