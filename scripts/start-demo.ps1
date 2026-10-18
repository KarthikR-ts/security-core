<#
.SYNOPSIS
    Start the Aegis Sentinel demo and open it in your browser.

.DESCRIPTION
    One command, one URL. This script:

      1. Opens an SSH tunnel to the LinuxONE host (loopback only).
      2. Waits for the dashboard API to answer through that tunnel.
      3. Opens http://localhost:8080 in your default browser.

    The dashboard API on the remote host serves BOTH the JSON API and the
    built React bundle, so everything is same-origin. No Vite dev server and
    no second port are involved.

    The tunnel must stay open for the demo. Close this window, or press
    Ctrl+C, to tear the tunnel down.

.PARAMETER Host
    LinuxONE host. Override with -Host.

.PARAMETER User
    SSH user. Override with -User.

.PARAMETER Key
    Path to the private key.

.PARAMETER Port
    Local port to forward. Override with -Port.

.PARAMETER Mode
    Which sensor the remote stack should be running: 'procfs' (live /proc
    sensor, the default) or 'replay' (deterministic fixtures). This script
    does NOT change the remote mode - it only reports what it finds, so you
    never silently swap a live sensor for fixtures mid-demo.

.EXAMPLE
    .\start-demo.ps1
    .\start-demo.ps1 -Mode replay
#>

[CmdletBinding()]
param(
    [string]$Host        = '148.100.99.33',
    [string]$User        = 'linux1',
    [string]$Key         = "$env:USERPROFILE\.ssh\ibm_z",
    [int]   $Port        = 8080,
    [ValidateSet('procfs', 'replay')]
    [string]$Mode        = 'procfs',
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'

# ── Preflight: fail fast and legibly ────────────────────────────────

if (-not (Get-Command ssh -ErrorAction SilentlyContinue)) {
    Write-Host "ssh not found. Install the OpenSSH client:" -ForegroundColor Red
    Write-Host "  Add-WindowsCapability -Online -Name OpenSSH.Client~~~~0.0.1.0" -ForegroundColor DarkGray
    exit 1
}

# Accept the .pem next to the key as well, since IBM ships one.
$keyPath = $null
foreach ($candidate in @($Key, "$Key.pem", "$env:USERPROFILE\.ssh\ibm_z.pem")) {
    if ($candidate -and (Test-Path $candidate)) { $keyPath = (Resolve-Path $candidate).Path; break }
}

if (-not $keyPath) {
    Write-Host "Private key not found. Looked for:" -ForegroundColor Red
    foreach ($c in @($Key, "$Key.pem", "$env:USERPROFILE\.ssh\ibm_z.pem")) {
        Write-Host "  $c" -ForegroundColor DarkGray
    }
    Write-Host "Pass the correct path with -Key <path>." -ForegroundColor Red
    exit 1
}

Write-Host "Aegis Sentinel" -ForegroundColor Cyan
Write-Host "  key    : $keyPath"
Write-Host "  tunnel : localhost:$Port  ->  $User@$Host`:8080 (loopback only)"
Write-Host "  url    : http://localhost:$Port"
Write-Host ""

# ── Open the tunnel ─────────────────────────────────────────────────

$sshArgs = @(
    '-N'                      # no remote command; pure tunnel
    '-o', 'ExitOnForwardFailure=yes'
    '-o', 'StrictHostKeyChecking=accept-new'
    '-o', 'ServerAliveInterval=30'
    '-o', 'ServerAliveCountMax=3'
    '-i', $keyPath
    '-L', "127.0.0.1:${Port}:127.0.0.1:8080"
    "$User@$Host"
)

Write-Host "Opening SSH tunnel..." -ForegroundColor DarkGray
$tunnel = Start-Process -FilePath 'ssh' -ArgumentList $sshArgs -PassThru -WindowStyle Hidden

# ── Wait for the API to answer through the tunnel ───────────────────

$base    = "http://localhost:$Port"
$ready   = $false
$deadline = (Get-Date).AddSeconds(30)

while ((Get-Date) -lt $deadline) {
    if ($tunnel.HasExited) {
        Write-Host "`nSSH tunnel exited immediately (code $($tunnel.ExitCode))." -ForegroundColor Red
        Write-Host "Check the host, key, and that the remote stack is running:" -ForegroundColor DarkGray
        Write-Host "  bash ~/aegis/scripts/aegis-ctl.sh status" -ForegroundColor DarkGray
        exit 1
    }
    try {
        $health = Invoke-RestMethod -Uri "$base/api/health" -TimeoutSec 3
        $ready = $true
        break
    } catch {
        Start-Sleep -Milliseconds 700
    }
}

if (-not $ready) {
    Write-Host "`nThe tunnel is up but the API did not answer within 30s." -ForegroundColor Yellow
    Write-Host "The remote stack may not be started. Try:" -ForegroundColor DarkGray
    Write-Host "  ssh -i `"$keyPath`" $User@$Host 'bash ~/aegis/scripts/aegis-ctl.sh start $Mode'" -ForegroundColor DarkGray
    exit 1
}

# ── Report what we found, honestly ──────────────────────────────────

$platform = $health.platform
Write-Host "Connected. Remote reports:" -ForegroundColor Green
Write-Host "  status        : $($health.status)"
Write-Host "  architecture  : $($platform.source_arch)  ($($platform.hardware))"
Write-Host "  capture mode  : $($platform.capture_mode)"
Write-Host "  sensor kind   : $($platform.sensor_kind)"
Write-Host "  is eBPF       : $($platform.sensor_is_ebpf)"
Write-Host "  events cached : $($health.events_cached)"
Write-Host ""

if ($platform.capture_mode -ne $Mode) {
    $actual = $platform.capture_mode
    Write-Warning "Remote is running '$actual', not the requested '$Mode'."
    Write-Warning "Switch it with:  bash ~/aegis/scripts/aegis-ctl.sh restart $Mode"
    Write-Host ""
}

# ── Open the browser ────────────────────────────────────────────────

if (-not $NoBrowser) {
    Start-Process $base
    Write-Host "Browser opened. Keep this window open - closing it closes the tunnel." -ForegroundColor Cyan
} else {
    Write-Host "Open: $base   (keep this window open)" -ForegroundColor Cyan
}

Write-Host "Press Ctrl+C to close the tunnel and exit." -ForegroundColor DarkGray

try {
    while (-not $tunnel.HasExited) { Start-Sleep -Seconds 1 }
} catch {
    # Ctrl+C lands here.
}

Write-Host "`nTunnel closed." -ForegroundColor DarkGray