#Requires -RunAsAdministrator
# Disposable hosted Windows runner only. Installs/removes one real local service,
# generates test-only credentials and sends native basic metrics to loopback.
[CmdletBinding(DefaultParameterSetName='Package')]
param(
    [Parameter(Mandatory,ParameterSetName='Executable')][string]$Executable,
    [Parameter(Mandatory,ParameterSetName='Package')][string]$PackageArchive,
    [string]$ResultFile = (Join-Path $PSScriptRoot '../../artifacts/windows-rust-native.json')
)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../..'))
if ($PackageArchive) { $PackageArchive = (Resolve-Path -LiteralPath $PackageArchive).Path }
if ($Executable) { $Executable = (Resolve-Path -LiteralPath $Executable).Path }
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
$result = @{schemaVersion='tracebolt.rust-native-acceptance.v1'; status='failed'; platform='windows'; packagedArtifact=$false; install=$false; activated=$false; mutualTLS=$false; nativeMetrics=$false; localReceipt=$false; boundedStop=$false; stopMilliseconds=$null; restart=$false; removal=$false; rebootTested=$false; productionLinuxManager=$false}
$result.localDiagnosticState = 'not-observed'; $result.localAttemptResult = 'not-observed'
$result.localReceiptPresent = $false; $result.localReceiptAtLeastPeerSequence = $false; $result.localAttemptAccepted = $false
$result.healthLockFile = 'not-probed'; $result.healthSnapshotFile = 'not-probed'; $result.healthTemporaryFile = 'not-probed'
$result.healthFileProbeComplete = $false
function ConvertTo-NativeEvidenceHealthCode([object]$Value) {
    # Return only source-fixed vocabulary, never an unknown status value/prose.
    foreach ($code in @(
        'not-observed','attempt-in-progress','attempt-interrupted','registration-pending','pending-approval','accepted',
        'receipt-stale','certificate-expiring','configuration-invalid','state-unavailable','state-corrupt','clock-invalid',
        'collection-failed','transport-timeout','transport-dns-failed','transport-tls-failed','transport-connection-refused',
        'transport-unreachable','transport-unclassified','authentication-rejected','manager-rejected','protocol-unavailable',
        'receipt-invalid','certificate-expired','certificate-not-yet-valid','enrollment-expired','enrollment-revoked',
        'enrollment-terminated','unclassified-failure','health-unavailable'
    )) {
        if ($Value -is [string] -and $Value -ceq $code) { return $code }
    }
    return 'unrecognized'
}
function Get-NativeReceiptEvidence([object]$Local, [object]$Accepted) {
    # Observations only. The original acceptance assertions below stay unchanged.
    # Neither receipt identity/sequence/time nor raw status JSON is exported.
    return @{
        localDiagnosticState = ConvertTo-NativeEvidenceHealthCode $Local.state
        localAttemptResult = ConvertTo-NativeEvidenceHealthCode $Local.lastAttemptResult
        localReceiptPresent = [bool]($null -ne $Local.lastAcceptedReceipt)
        localReceiptAtLeastPeerSequence = [bool]($Local.lastAcceptedReceipt.sequence -ge $Accepted.sequence)
        localAttemptAccepted = [bool]($Local.lastAttemptResult -eq 'accepted')
    }
}
function ConvertTo-NativeHealthFileOutcome([object]$Attributes, [Exception]$Failure = $null) {
    if ($null -ne $Failure) {
        $cause = $Failure.GetBaseException()
        if ($cause -is [IO.FileNotFoundException] -or $cause -is [IO.DirectoryNotFoundException]) { return 'missing' }
        if ($cause -is [UnauthorizedAccessException]) { return 'denied' }
        if ($cause -is [ComponentModel.Win32Exception]) {
            if ($cause.NativeErrorCode -in @(2,3)) { return 'missing' }
            if ($cause.NativeErrorCode -eq 5) { return 'denied' }
        }
        return 'unavailable'
    }
    if ($Attributes -isnot [IO.FileAttributes]) { return 'unavailable' }
    if ($Attributes -band [IO.FileAttributes]::ReparsePoint) { return 'reparse' }
    if ($Attributes -band [IO.FileAttributes]::Directory) { return 'not-file' }
    return 'ordinary-file'
}
function Get-NativeHealthFileEvidence([string]$DataDirectory) {
    $observed = @{healthLockFile='unavailable'; healthSnapshotFile='unavailable'; healthTemporaryFile='unavailable'; healthFileProbeComplete=$false}
    $lease = $null
    try {
        # This caller has already installed into paths confirmed absent on this
        # disposable runner. Retain ordinary no-follow ancestors during these
        # metadata-only leaf queries; never traverse a reparse parent or read bytes.
        $state = Join-Path $DataDirectory 'state'
        $lease = [Tracebolt.InstallDirectoryLease]::Acquire([string[]]@($state))
        foreach ($pair in @(@('healthLockFile','health-v1.lock'), @('healthSnapshotFile','health-v1.json'), @('healthTemporaryFile','health-v1.tmp'))) {
            try {
                $attributes = [IO.File]::GetAttributes((Join-Path $state $pair[1]))
                $observed[$pair[0]] = ConvertTo-NativeHealthFileOutcome $attributes
            } catch { $observed[$pair[0]] = ConvertTo-NativeHealthFileOutcome $null $_.Exception }
        }
        $observed.healthFileProbeComplete = @($observed.healthLockFile,$observed.healthSnapshotFile,$observed.healthTemporaryFile |
            Where-Object { $_ -cnotin @('ordinary-file','missing') }).Count -eq 0
    } catch {
        # Parent/lease failure is not proof that any leaf is absent.
        $parent = ConvertTo-NativeHealthFileOutcome $null $_.Exception
        if ($parent -ceq 'denied') { foreach ($field in @('healthLockFile','healthSnapshotFile','healthTemporaryFile')) { $observed[$field] = 'denied' } }
    } finally { if ($null -ne $lease) { $lease.Dispose() } }
    return $observed
}
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
    $installer = Join-Path $repo 'deploy/windows-rust/Install-Tracebolt.ps1'
    $uninstaller = Join-Path $repo 'deploy/windows-rust/Uninstall-Tracebolt.ps1'
    if ($Executable) {
        # The executable-only developer entry point must also use a fresh exact
        # package, never bypass the installer's manifest/namespace validation.
        $prepared = Join-Path $temporary 'developer-package'
        & (Join-Path $repo 'deploy/windows-rust/Write-Package.ps1') -Executable $Executable -OutputDirectory $prepared
        $PackageArchive = "$prepared.zip"
    }
    if ($PackageArchive) {
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $expected = @('Install-Tracebolt.ps1','Package-Preflight.ps1','README.md','SHA256SUMS.txt','Uninstall-Tracebolt.ps1','tracebolt-windows-agent.exe') | Sort-Object
        $zip = [IO.Compression.ZipFile]::OpenRead($PackageArchive)
        try {
            $names = @($zip.Entries | ForEach-Object { $_.FullName } | Sort-Object)
            if (($names -join '|') -cne ($expected -join '|')) { throw 'Package must contain only the exact six root-level entries.' }
        } finally { $zip.Dispose() }
        $packageDirectory = Join-Path $temporary 'package'
        Expand-Archive -LiteralPath $PackageArchive -DestinationPath $packageDirectory
        $lines = @(Get-Content -LiteralPath (Join-Path $packageDirectory 'SHA256SUMS.txt'))
        $seen = @{}
        foreach ($line in $lines) {
            if ($line -cnotmatch '^([a-f0-9]{64})  ([^/\\]+)$') { throw 'Invalid package checksum syntax.' }
            $name = $Matches[2]; $hash = $Matches[1]
            if ($name -ceq 'SHA256SUMS.txt' -or $expected -cnotcontains $name -or $seen.ContainsKey($name)) { throw 'Invalid package checksum allowlist.' }
            if ((Get-FileHash -LiteralPath (Join-Path $packageDirectory $name) -Algorithm SHA256).Hash.ToLowerInvariant() -cne $hash) { throw 'Package checksum mismatch.' }
            $seen[$name] = $true
        }
        if ($seen.Count -ne 5) { throw 'Package checksums are incomplete.' }
        $Executable = Join-Path $packageDirectory 'tracebolt-windows-agent.exe'
        $installer = Join-Path $packageDirectory 'Install-Tracebolt.ps1'
        $uninstaller = Join-Path $packageDirectory 'Uninstall-Tracebolt.ps1'
        $result.packagedArtifact = $true
    }
    Push-Location $repo
    try {
        go build -o $fixtureExe ./tests/rustagent/cmd/nativefixture
        if ($LASTEXITCODE -ne 0) { throw 'Could not build the disposable protocol fixture.' }
    } finally { Pop-Location }
    $fixture = Start-Process -FilePath $fixtureExe -ArgumentList @('--directory', ('"{0}"' -f $fixtureDirectory)) -PassThru -RedirectStandardOutput (Join-Path $temporary 'fixture.stdout') -RedirectStandardError (Join-Path $temporary 'fixture.stderr')
    $ready = Wait-ForJson (Join-Path $fixtureDirectory 'ready.json') { param($v) $v.loopbackOnly -eq $true } 30
    if (([Uri]$ready.managerOrigin).Host -ne '127.0.0.1' -or ([Uri]$ready.agentOrigin).Host -ne '127.0.0.1') { throw 'Fixture must be loopback-only.' }
    $stagingAuthorized = $true
    $installOutput = @(& $installer -ManagerOrigin $ready.managerOrigin -ServerCAFile $ready.serverCAFile -Executable $Executable -IntervalSeconds 30 -AcknowledgeBasicMetrics)
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
    $deadline = [DateTime]::UtcNow.AddSeconds(15)
    do {
        $local = (& $Executable status --directory $dataDirectory --json) | ConvertFrom-Json
        if ($LASTEXITCODE -ne 0) { throw 'Local receipt diagnostics command failed.' }
        $receiptEvidence = Get-NativeReceiptEvidence $local $accepted
        foreach ($field in $receiptEvidence.Keys) { $result[$field] = $receiptEvidence[$field] }
        if ($local.lastAcceptedReceipt.sequence -ge $accepted.sequence -and $local.lastAttemptResult -eq 'accepted') { break }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($local.lastAcceptedReceipt.sequence -lt $accepted.sequence -or $local.lastAttemptResult -ne 'accepted') { throw 'Validated receipt was not durably visible in local diagnostics.' }
    $result.localReceipt=$true
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    Stop-Service $serviceName
    $controller = Get-Service $serviceName
    try { $controller.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) } finally { $controller.Dispose() }
    $stopwatch.Stop()
    $result.stopMilliseconds=$stopwatch.ElapsedMilliseconds
    if ($stopwatch.Elapsed.TotalSeconds -ge 25) { throw 'Service stop exceeded its bounded in-flight operation budget.' }
    $result.boundedStop=$true
    $retained = (& $Executable status --directory $dataDirectory --json) | ConvertFrom-Json
    if ($LASTEXITCODE -ne 0 -or $retained.lastAcceptedReceipt.sequence -lt $local.lastAcceptedReceipt.sequence) { throw 'Service stop lost or rolled back the local receipt.' }
    $before = Read-OptionalJson (Join-Path $fixtureDirectory 'accepted.json')
    if ($retained.lastAcceptedReceipt.sequence -ne $before.sequence) { throw 'Stopped service diagnostics do not match the settled peer receipt.' }
    Start-Service $serviceName
    $restarted = Wait-ForJson (Join-Path $fixtureDirectory 'accepted.json') { param($v) $v.count -gt $before.count -and $v.sequence -gt $before.sequence } 120
    if (!$restarted.accepted) { throw 'Service restart did not resume acknowledged telemetry.' }
    $result.restart=$true
    & $uninstaller
    $deadline=[DateTime]::UtcNow.AddSeconds(20)
    while ((Get-Service $serviceName -ErrorAction SilentlyContinue) -and [DateTime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds 500 }
    if (Get-Service $serviceName -ErrorAction SilentlyContinue) { throw 'Service removal did not complete.' }
    $result.removal=$true; $result.status='passed'
} finally {
    # Observe only our freshly installed CI paths, before the existing cleanup.
    # A probe failure must neither become "missing" nor skip that cleanup.
    if ($result.install) {
        try {
            $healthFiles = Get-NativeHealthFileEvidence $dataDirectory
            foreach ($field in $healthFiles.Keys) { $result[$field] = $healthFiles[$field] }
        } catch { $result.healthFileProbeComplete = $false }
    }
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
Write-Host 'Native Windows basic agent acceptance passed: install, exact-key approval, activation, mutual TLS telemetry, local receipt, bounded stop, service restart and removal.'
