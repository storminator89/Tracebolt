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
if ((Get-Service -Name $name -ErrorAction SilentlyContinue) -or (Test-Path $bin) -or (Test-Path $data)) {
    throw 'Existing installation or retained state found. No automatic adoption, upgrade or reset is supported.'
}
foreach ($file in $required) {
    if (!(Test-Path -LiteralPath $file -PathType Leaf)) { throw 'Required executable or protected TLS file is missing.' }
}
# Validate the exact Rust configuration and CA parser before any persistent mutation.
if (![Environment]::Is64BitOperatingSystem -or $env:PROCESSOR_ARCHITECTURE -ne 'AMD64') {
    throw 'This package supports native Windows x64 only.'
}
$validationArguments = @('validate-config','--manager-origin',$ManagerOrigin,'--mode',$mode,'--interval-seconds',"$IntervalSeconds")
if ($AgentOrigin) { $validationArguments += '--agent-origin',$AgentOrigin }
if ($AgentId) { $validationArguments += '--agent-id',$AgentId }
if ($ServerCAFile) { $validationArguments += '--server-ca-file',$ServerCAFile }
& $Executable @validationArguments
if ($LASTEXITCODE -ne 0) { throw 'Preflight rejected configuration or CA. No service, directory or identity was created.' }
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
New-Service -Name $name -BinaryPathName ('"{0}" service --directory "{1}"' -f $target,$data) -DisplayName 'Tracebolt Rust basic agent' -StartupType Disabled | Out-Null
Invoke-SC -Arguments @('config',$name,'obj=','NT AUTHORITY\LocalService')
Invoke-SC -Arguments @('sidtype',$name,'restricted')
New-Item -ItemType Directory -Path $bin,$data | Out-Null
Protect-Directory $bin 'ReadAndExecute'
Protect-Directory $data 'ReadAndExecute'
$state = Join-Path $data 'state'
New-Item -ItemType Directory -Path $state | Out-Null
Protect-Directory $state 'Modify'
Copy-Item -LiteralPath $Executable -Destination $target
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
Invoke-SC -Arguments @('config',$name,'start=','delayed-auto')
Start-Service -Name $name
Write-Host 'Service started. Automatic onboarding needs no token. Review the new device and its public key fingerprint in the manager; after approval reporting starts automatically. Confirm a fresh accepted report, not only service uptime.'
