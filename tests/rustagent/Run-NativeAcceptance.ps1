#Requires -RunAsAdministrator
# Disposable hosted Windows runner only. Installs/removes one real local service,
# generates test-only credentials and sends native basic metrics to loopback.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Executable,
    [string]$ResultFile = (Join-Path $PSScriptRoot '../../artifacts/windows-rust-native.json')
)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
$Executable = (Resolve-Path -LiteralPath $Executable).Path
$ResultFile = [IO.Path]::GetFullPath($ResultFile)
$serviceName = 'TraceboltRustAgent'
$binaryDirectory = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Tracebolt Rust'
$dataDirectory = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'TraceboltRust'
if ((Get-Service $serviceName -ErrorAction SilentlyContinue) -or (Test-Path $binaryDirectory) -or (Test-Path $dataDirectory)) {
    throw 'Native acceptance requires a disposable fresh runner; existing service or state will not be adopted or removed.'
}
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('tracebolt-rust-native-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
$fixtureDirectory = Join-Path $temporary 'peer'
$fixtureExe = Join-Path $temporary 'nativefixture.exe'
$fixture = $null
$stagingAuthorized = $false
$result = @{schemaVersion='tracebolt.rust-native-acceptance.v1'; status='failed'; platform='windows'; install=$false; activated=$false; mutualTLS=$false; nativeMetrics=$false; restart=$false; removal=$false; rebootTested=$false; productionLinuxManager=$false}
function Read-OptionalJson([string]$Path) {
    if (!(Test-Path -LiteralPath $Path)) { return $null }
    try { return Get-Content -Raw -LiteralPath $Path | ConvertFrom-Json } catch { return $null }
}
function Wait-ForJson([string]$Path, [scriptblock]$Accept, [int]$Seconds) {
    $deadline = [DateTime]::UtcNow.AddSeconds($Seconds)
    do {
        if ($fixture.HasExited) { throw 'Loopback fixture exited before acceptance completed.' }
        $value = Read-OptionalJson $Path
        if ($null -ne $value -and (& $Accept $value)) { return $value }
        Start-Sleep -Milliseconds 500
    } while ([DateTime]::UtcNow -lt $deadline)
    throw 'Timed out waiting for native acceptance evidence.'
}
try {
    Push-Location $repo
    try {
        go build -o $fixtureExe ./tests/rustagent/cmd/nativefixture
        if ($LASTEXITCODE -ne 0) { throw 'Could not build the disposable protocol fixture.' }
    } finally { Pop-Location }
    $fixture = Start-Process -FilePath $fixtureExe -ArgumentList @('--directory', ('"{0}"' -f $fixtureDirectory)) -PassThru -RedirectStandardOutput (Join-Path $temporary 'fixture.stdout') -RedirectStandardError (Join-Path $temporary 'fixture.stderr')
    $ready = Wait-ForJson (Join-Path $fixtureDirectory 'ready.json') { param($v) $v.loopbackOnly -eq $true } 30
    if (([Uri]$ready.managerOrigin).Host -ne '127.0.0.1' -or ([Uri]$ready.agentOrigin).Host -ne '127.0.0.1') { throw 'Fixture must be loopback-only.' }
    $stagingAuthorized = $true
    $installOutput = @(& (Join-Path $repo 'deploy/windows-rust/Install-Tracebolt.ps1') -ManagerOrigin $ready.managerOrigin -ServerCAFile $ready.serverCAFile -Executable $Executable -IntervalSeconds 30 -AcknowledgeBasicMetrics)
    $fingerprints = @($installOutput | ForEach-Object {
        try {
            $item = ([string]$_) | ConvertFrom-Json -ErrorAction Stop
            if ($item.keyFingerprint -match '^[a-f0-9]{64}$') { $item.keyFingerprint }
        } catch { }
    } | Select-Object -Unique)
    if ($fingerprints.Count -ne 1) { throw 'Installer did not expose exactly one local public key fingerprint.' }
    $service = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($service.State -ne 'Running' -or $service.StartName -ne 'NT AUTHORITY\LocalService') { throw 'Installed service is not running under LocalService.' }
    $result.install = $true
    $pending = Wait-ForJson (Join-Path $fixtureDirectory 'pending.json') { param($v) $v.pending -eq $true } 150
    if ($pending.keyFingerprint -ne $fingerprints[0]) { throw 'Pending key differs from the installed endpoint key.' }
    if (Test-Path (Join-Path $fixtureDirectory 'accepted.json')) { throw 'Telemetry arrived before fingerprint approval.' }
    # The only automatic approval is this disposable fixture's exact locally
    # compared key. It does not call or change a production manager.
    [IO.File]::WriteAllText((Join-Path $fixtureDirectory 'expected-fingerprint.txt'), $fingerprints[0], (New-Object Text.UTF8Encoding($false)))
    $accepted = Wait-ForJson (Join-Path $fixtureDirectory 'accepted.json') { param($v) $v.accepted -eq $true -and $v.count -ge 1 } 480
    if (!$accepted.mutualTLS -or !$accepted.activated -or !$accepted.cpuAvailable -or !$accepted.memoryAvailable -or !$accepted.diskAvailable) { throw 'Native metrics, activation or mutual TLS acceptance is incomplete.' }
    $result.activated=$true; $result.mutualTLS=$true; $result.nativeMetrics=$true
    Stop-Service $serviceName
    $controller = Get-Service $serviceName
    try { $controller.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) } finally { $controller.Dispose() }
    $before = Read-OptionalJson (Join-Path $fixtureDirectory 'accepted.json')
    Start-Service $serviceName
    $restarted = Wait-ForJson (Join-Path $fixtureDirectory 'accepted.json') { param($v) $v.count -gt $before.count -and $v.sequence -gt $before.sequence } 120
    if (!$restarted.accepted) { throw 'Service restart did not resume acknowledged telemetry.' }
    $result.restart=$true
    & (Join-Path $repo 'deploy/windows-rust/Uninstall-Tracebolt.ps1')
    $deadline=[DateTime]::UtcNow.AddSeconds(20)
    while ((Get-Service $serviceName -ErrorAction SilentlyContinue) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 500 }
    if (Get-Service $serviceName -ErrorAction SilentlyContinue) { throw 'Service removal did not complete.' }
    $result.removal=$true; $result.status='passed'
} finally {
    if ($stagingAuthorized) {
        $service = Get-Service $serviceName -ErrorAction SilentlyContinue
        if ($service) {
            Stop-Service $serviceName -ErrorAction SilentlyContinue
            try { $service.WaitForStatus('Stopped',[TimeSpan]::FromSeconds(30)) } catch { }
            $service.Dispose()
            & "$env:SystemRoot\System32\sc.exe" delete $serviceName | Out-Null
        }
    }
    if ($null -ne $fixture -and !$fixture.HasExited) { Stop-Process -Id $fixture.Id -Force }
    # These paths were confirmed absent before this explicitly disposable run.
    if ($stagingAuthorized) {
        if (Test-Path $binaryDirectory) { Remove-Item -LiteralPath $binaryDirectory -Recurse -Force }
        if (Test-Path $dataDirectory) { Remove-Item -LiteralPath $dataDirectory -Recurse -Force }
    }
    if (Test-Path $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
    New-Item -ItemType Directory -Path (Split-Path $ResultFile -Parent) -Force | Out-Null
    $result | ConvertTo-Json | Set-Content -LiteralPath $ResultFile -Encoding utf8
}
Write-Host 'Native Windows basic agent acceptance passed: install, exact-key approval, activation, mutual TLS telemetry, service restart and removal.'
