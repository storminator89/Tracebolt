#Requires -RunAsAdministrator
$ErrorActionPreference = 'Stop'
$name = 'TraceboltRustAgent'
$service = Get-Service -Name $name -ErrorAction Stop
if ($service.Status -ne 'Stopped') {
    Stop-Service -Name $name
    $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30))
}
$service.Dispose()
& "$env:SystemRoot\System32\sc.exe" delete $name | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Service removal failed.' }
Write-Host 'Service removed. Protected credentials, binary and sequence state retained. Revoke the endpoint in the manager before deliberate archival/removal; never reuse its identity with reset counters.'
