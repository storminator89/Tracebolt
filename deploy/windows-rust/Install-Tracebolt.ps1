#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ManagerOrigin,
    [string]$ServerCAFile,
    [string]$AgentOrigin,
    [string]$InvitationBootstrap,
    [string]$AgentId,
    [string]$CredentialDirectory,
    [string]$Executable = (Join-Path $PSScriptRoot 'tracebolt-windows-agent.exe'),
    [ValidateRange(30,3600)][int]$IntervalSeconds = 60,
    [switch]$AcknowledgeBasicMetrics,
    [switch]$FreshApprovedIdentity
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Package-Preflight.ps1')
if (!$AcknowledgeBasicMetrics) {
    throw 'Review CPU/RAM/system-volume/uptime transmission and supply -AcknowledgeBasicMetrics. Default onboarding generates a new local key automatically and awaits manager approval; no token is required.'
}
$mode = 'auto'
$required = @($Executable)
if ($CredentialDirectory) {
    if (!$FreshApprovedIdentity -or !$AgentId -or $InvitationBootstrap) { throw 'Preprovided mode requires a fresh approved identity and AgentId; do not combine it with an invitation.' }
    $mode = 'preprovided'
    $required += (Join-Path $CredentialDirectory 'client.pem'), (Join-Path $CredentialDirectory 'client.key')
    if (!$ServerCAFile -and (Test-Path (Join-Path $CredentialDirectory 'server-ca.pem'))) { $ServerCAFile = Join-Path $CredentialDirectory 'server-ca.pem' }
} elseif ($InvitationBootstrap) {
    $mode = 'invitation'
    $required += $InvitationBootstrap
} elseif ($AgentId -or $FreshApprovedIdentity) { throw 'Automatic onboarding allocates its own identity; omit AgentId/FreshApprovedIdentity.' }
if ($ServerCAFile) { $required += $ServerCAFile }
$name = 'TraceboltRustAgent'
$bin = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Tracebolt Rust'
$data = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'TraceboltRust'
if ((Get-Service -Name $name -ErrorAction SilentlyContinue) -or (Test-Path -LiteralPath $bin) -or (Test-Path -LiteralPath $data)) {
    throw 'Existing installation or retained state found. No automatic adoption, upgrade or reset is supported.'
}
foreach ($file in $required) {
    if (!(Test-Path -LiteralPath $file -PathType Leaf)) { throw 'Required executable or protected TLS file is missing.' }
    $null = Assert-TraceboltPlainPath $file
}
# Validate the exact Rust configuration and CA parser before any persistent mutation.
if (![Environment]::Is64BitOperatingSystem -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    throw 'This package supports native Windows x64 only.'
}
$package = $null
$targetLock = $null
Initialize-TraceboltInstallerType
# Pin every existing target ancestor before reading its ACL. These are real
# native read/no-follow handles, retained until startup or failure completes.
$targetLease = [Tracebolt.InstallDirectoryLease]::Acquire([string[]]@((Split-Path -Parent $bin), (Split-Path -Parent $data)))
try {
    Assert-TraceboltInstallParent (Split-Path -Parent $bin) $targetLease
    Assert-TraceboltInstallParent (Split-Path -Parent $data) $targetLease
    # Do not invoke a candidate before strict package/hash and PE checks.
    $package = Open-TraceboltPackage -Executable $Executable -PackageDirectory $PSScriptRoot
    $Executable = $package.ExecutablePath
    $validationArguments = @('validate-config','--manager-origin',$ManagerOrigin,'--mode',$mode,'--interval-seconds',"$IntervalSeconds")
    if ($mode -ne 'preprovided') { $validationArguments += '--check-manager' }
    if ($AgentOrigin) { $validationArguments += '--agent-origin',$AgentOrigin }
    if ($AgentId) { $validationArguments += '--agent-id',$AgentId }
    if ($ServerCAFile) { $validationArguments += '--server-ca-file',$ServerCAFile }
    if ($mode -eq 'invitation') { $validationArguments += '--bootstrap',$InvitationBootstrap }
    if ($mode -eq 'preprovided') { $validationArguments += '--credential-directory',$CredentialDirectory }
    & $Executable @validationArguments
    if ($LASTEXITCODE -ne 0) { throw 'Preflight rejected configuration, CA or manager compatibility. No service, directory or identity was created. Follow the safe diagnostic code above; use matching manager/frontend and Rust basic packages.' }
    function Invoke-SC([string[]]$Arguments) {
        & "$env:SystemRoot\System32\sc.exe" @Arguments | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'Windows service configuration failed; staging is retained for inspection.' }
    }
    function Protect-Directory([string]$Path, [string]$ServiceRights) {
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sid in @('S-1-5-18','S-1-5-32-544')) {
            $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
            $acl.AddAccessRule($rule)
        }
        $serviceSid = (New-Object System.Security.Principal.NTAccount("NT SERVICE\$name")).Translate([System.Security.Principal.SecurityIdentifier])
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($serviceSid,$ServiceRights,'ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $Path -AclObject $acl
    }
    # Stage disabled. Automatic enrollment generates its own key; no invitation token is requested.
    $target = Join-Path $bin 'tracebolt-windows-agent.exe'
    New-TraceboltProtectedDirectory $bin $targetLease
    $targetLease.Pin($bin)
    New-TraceboltProtectedDirectory $data $targetLease
    $targetLease.Pin($data)
    New-Service -Name $name -BinaryPathName ('"{0}" service --directory "{1}"' -f $target,$data) -DisplayName 'Tracebolt Rust basic agent' -StartupType Disabled | Out-Null
    Invoke-SC -Arguments @('config',$name,'obj=','NT AUTHORITY\LocalService')
    Invoke-SC -Arguments @('sidtype',$name,'restricted')
    Protect-Directory $bin 'ReadAndExecute'
    Protect-Directory $data 'ReadAndExecute'
    $state = Join-Path $data 'state'
    New-TraceboltProtectedDirectory $state $targetLease
    $targetLease.Pin($state)
    Protect-Directory $state 'Modify'
    # Copy from the exact verified, still-locked handle, never reopen the input path.
    $output = [IO.File]::Open($target, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $package.ExecutableStream.Position = 0; $package.ExecutableStream.CopyTo($output); $output.Flush($true) } finally { $output.Dispose() }
    $targetLock = [IO.File]::Open($target, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    if ((Get-TraceboltStreamHash $targetLock) -cne $package.SHA256) { throw 'Installed executable checksum mismatch; disabled staging retained.' }
    if ($mode -eq 'preprovided') {
        foreach ($leaf in @('client.pem','client.key')) {
            Copy-Item -LiteralPath (Join-Path $CredentialDirectory $leaf) -Destination (Join-Path $data $leaf)
        }
    }
    if ($ServerCAFile) { Copy-Item -LiteralPath $ServerCAFile -Destination (Join-Path $data 'server-ca.pem') }
    $config = @{
        schemaVersion = 'tracebolt.rust-windows-basic.v1'; managerOrigin = $ManagerOrigin;
        agentId = $AgentId; agentOrigin = $AgentOrigin; enrollmentMode = $mode;
        basicMetricsAcknowledged = $true; intervalSeconds = $IntervalSeconds
    }
    $json = $config | ConvertTo-Json
    [IO.File]::WriteAllText((Join-Path $data 'config.json'), $json, (New-Object Text.UTF8Encoding($false)))
    $initArguments = @('init','--directory',$data)
    if ($mode -eq 'invitation') { $initArguments += '--bootstrap',$InvitationBootstrap }
    & $target @initArguments
    if ($LASTEXITCODE -ne 0) { throw 'Initialization failed. Service remains disabled. Do not delete or reset sender state.' }
    if ($mode -eq 'invitation') {
        & $target claim-invitation --directory $data
        if ($LASTEXITCODE -ne 0) { throw 'Optional invitation claim failed. Service remains disabled; state retained. Retry the claim-invitation command with hidden local input.' }
    }
    Invoke-SC -Arguments @('failure',$name,'reset=','86400','actions=','restart/60000/restart/60000/restart/60000')
    # A full-path atomic health rename needs FILE_ADD_FILE on its destination
    # directory. Hand off only the exact, finally protected state leaf before
    # enabling the first service cycle; all other pins remain held. A failed
    # protection check must leave this fresh service disabled, not auto-startable.
    $targetLease.HandoffRuntimeStateForServiceStart()
    Invoke-SC -Arguments @('config',$name,'start=','delayed-auto')
    Start-Service -Name $name
    Write-Host 'Service started. Automatic onboarding needs no token. Review the new device and its public key fingerprint in the manager; after approval reporting starts automatically. Confirm a fresh accepted report, not only service uptime.'
} finally {
    if ($null -ne $targetLock) { $targetLock.Dispose() }
    if ($null -ne $package) { foreach ($stream in $package.Streams) { $stream.Dispose() } }
    $targetLease.Dispose()
}
