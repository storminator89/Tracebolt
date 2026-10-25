#requires -Version 5.1
<#
.SYNOPSIS
Build and run an isolated, synthetic Tracebolt demo on Windows loopback.
.DESCRIPTION
Keep this terminal open. Ctrl+C stops only the manager started by this script.
Each invocation creates a new session; existing demo databases are never reused.
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 65535)]
    [int]$Port = 8787,

    [ValidateNotNullOrEmpty()]
    [string]$GoExecutable = 'go.exe',

    [switch]$NoBrowser
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-Application {
    param([string]$Name)
    $command = Get-Command -Name $Name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $command) {
        throw "Required executable not found: $Name. Install the documented toolchain or supply -GoExecutable."
    }
    return $command.Source
}

function Get-CheckedVersion {
    param([string]$Executable, [string[]]$Arguments)
    $output = @(& $Executable @Arguments)
    if ($LASTEXITCODE -ne 0) {
        throw "Version check failed for $Executable (exit $LASTEXITCODE)."
    }
    return ($output -join "`n").Trim()
}

function Invoke-CheckedCommand {
    param([string]$Executable, [string[]]$Arguments)
    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed: $Executable (exit $LASTEXITCODE). No demo manager was started."
    }
}

function Assert-FreeDemoPort {
    param([int]$Value)
    $probe = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Loopback, $Value)
    try {
        $probe.Server.ExclusiveAddressUse = $true
        $probe.Start()
    }
    catch {
        throw "Loopback port $Value is unavailable. Choose another -Port; existing processes will not be stopped or reused."
    }
    finally {
        $probe.Stop()
    }
}

function Read-DemoJson {
    param([System.Net.Http.HttpClient]$Client, [string]$Address)
    $response = $Client.GetAsync($Address).GetAwaiter().GetResult()
    try {
        if ([int]$response.StatusCode -ne 200) {
            throw 'The demo endpoint is not ready.'
        }
        return ($response.Content.ReadAsStringAsync().GetAwaiter().GetResult() | ConvertFrom-Json)
    }
    finally {
        $response.Dispose()
    }
}

if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This launcher requires Windows. See docs/local-demo.md for its scope.'
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$webRoot = Join-Path $repositoryRoot 'web'
$webDist = Join-Path $webRoot 'dist'
if (-not (Test-Path -LiteralPath (Join-Path $repositoryRoot 'cmd\manager\main.go') -PathType Leaf) -or
    -not (Test-Path -LiteralPath (Join-Path $webRoot 'package-lock.json') -PathType Leaf)) {
    throw 'Run the launcher from a complete Tracebolt checkout; required source or dependency lock files are missing.'
}

$goPath = Resolve-Application $GoExecutable
$nodePath = Resolve-Application 'node.exe'
# Use the native Windows npm entry point, without changing PowerShell policy.
$npmPath = Resolve-Application 'npm.cmd'
$goVersion = Get-CheckedVersion $goPath @('version')
if ($goVersion -notmatch '^go version go1\.27\.1 windows/(?<arch>[a-z0-9]+)$') {
    throw "Go 1.27.1 for Windows is required; found: $goVersion. Use -GoExecutable for an existing matching toolchain."
}
$goHostArch = $Matches['arch']
$nodeVersion = Get-CheckedVersion $nodePath @('--version')
if ($nodeVersion -notmatch '^v24\.\d+\.\d+$') {
    throw "Node.js 24 is required; found: $nodeVersion."
}
$npmVersion = Get-CheckedVersion $npmPath @('--version')
if ($npmVersion -notmatch '^\d+\.\d+\.\d+$') {
    throw 'npm did not return a supported version response.'
}
Assert-FreeDemoPort $Port

$sessionParent = Join-Path $repositoryRoot '.local\demo'
$sessionName = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N')
$sessionRoot = Join-Path $sessionParent $sessionName
New-Item -ItemType Directory -Path $sessionParent -Force | Out-Null
# No -Force here: an existing session must never be adopted or overwritten.
New-Item -ItemType Directory -Path $sessionRoot | Out-Null
$managerExecutable = Join-Path $sessionRoot 'manager.exe'
$database = Join-Path $sessionRoot 'state.db'
$stdoutLog = Join-Path $sessionRoot 'manager.stdout.log'
$stderrLog = Join-Path $sessionRoot 'manager.stderr.log'
$baseAddress = "http://127.0.0.1:$Port"
$managerProcess = $null
$httpClient = $null

Write-Host "Tracebolt synthetic demo | Go 1.27.1 | Node $nodeVersion | npm $npmVersion"
Write-Host "New session: $sessionRoot"

try {
    Push-Location -LiteralPath $repositoryRoot
    try {
        $target = @(& $goPath env GOOS GOARCH)
        if ($LASTEXITCODE -ne 0 -or $target.Count -ne 2 -or $target[0] -ne 'windows' -or $target[1] -ne $goHostArch) {
            throw 'Go is configured for a different target. Clear cross-compilation GOOS/GOARCH settings in this terminal before starting the native demo.'
        }
        Write-Host 'Building the demo manager from this checkout...'
        Invoke-CheckedCommand $goPath @('build', '-buildvcs=false', '-trimpath', '-o', $managerExecutable, './cmd/manager')
    }
    finally {
        Pop-Location
    }

    Push-Location -LiteralPath $webRoot
    try {
        $typescript = Join-Path $webRoot 'node_modules\.bin\tsc.cmd'
        $vite = Join-Path $webRoot 'node_modules\.bin\vite.cmd'
        if (-not (Test-Path -LiteralPath $typescript -PathType Leaf) -or -not (Test-Path -LiteralPath $vite -PathType Leaf)) {
            Write-Host 'Frontend dependencies are missing; installing the locked local dependency tree...'
            Invoke-CheckedCommand $npmPath @('ci', '--no-audit', '--no-fund')
        }
        Write-Host 'Building the matching dashboard...'
        Invoke-CheckedCommand $npmPath @('run', 'build')
    }
    finally {
        Pop-Location
    }
    if (-not (Test-Path -LiteralPath (Join-Path $webDist 'index.html') -PathType Leaf)) {
        throw 'The dashboard build did not produce web/dist/index.html.'
    }

    Assert-FreeDemoPort $Port
    # Start-Process joins ArgumentList with spaces. Quote the absolute path
    # arguments explicitly so a checkout path containing spaces stays intact.
    $managerArguments = @('--demo-only', '--port', [string]$Port, '--db', ('"' + $database + '"'), '--web', ('"' + $webDist + '"'))
    $managerProcess = Start-Process -FilePath $managerExecutable -ArgumentList $managerArguments -WorkingDirectory $repositoryRoot -WindowStyle Hidden -RedirectStandardOutput $stdoutLog -RedirectStandardError $stderrLog -PassThru

    Add-Type -AssemblyName System.Net.Http
    $httpHandler = New-Object System.Net.Http.HttpClientHandler
    $httpHandler.UseProxy = $false
    $httpHandler.AllowAutoRedirect = $false
    $httpClient = New-Object System.Net.Http.HttpClient($httpHandler)
    $httpClient.Timeout = [TimeSpan]::FromSeconds(2)
    $httpClient.MaxResponseContentBufferSize = 1048576
    $ready = $false
    $readyDeadline = [DateTime]::UtcNow.AddSeconds(30)
    while ([DateTime]::UtcNow -lt $readyDeadline) {
        if ($managerProcess.HasExited) {
            throw "The demo manager exited before readiness (exit $($managerProcess.ExitCode)). See $stderrLog."
        }
        try {
            $health = Read-DemoJson $httpClient "$baseAddress/api/health"
            $capabilities = Read-DemoJson $httpClient "$baseAddress/api/capabilities"
            $overview = Read-DemoJson $httpClient "$baseAddress/api/overview"
            $demoDevices = @($overview.devices)
            $unexpected = @($demoDevices | Where-Object { $_.synthetic -isnot [bool] -or -not $_.synthetic -or $_.source -ne 'synthetic' })
            if ($health.status -eq 'ok' -and $capabilities.demoOnly -is [bool] -and $capabilities.demoOnly -and
                $demoDevices.Count -eq 7 -and $unexpected.Count -eq 0 -and -not $managerProcess.HasExited) {
                $ready = $true
                break
            }
        }
        catch {
            # Startup may not yet have bound the socket. Do not print response
            # bodies or diagnostics from an unrelated process that raced us.
        }
        Start-Sleep -Milliseconds 250
    }
    if (-not $ready) {
        throw "The manager did not confirm a healthy demo-only session with exactly seven synthetic devices. See $stderrLog."
    }

    Write-Host "Ready: $baseAddress/#/overview"
    Write-Host 'Seven synthetic devices only. Keep this terminal open; press Ctrl+C here to stop this demo.'
    if (-not $NoBrowser) {
        try {
            Start-Process -FilePath "$baseAddress/#/overview" | Out-Null
        }
        catch {
            Write-Warning "The browser could not be opened. Open $baseAddress/#/overview manually."
        }
    }
    while (-not $managerProcess.HasExited) {
        Start-Sleep -Milliseconds 250
    }
    if ($managerProcess.ExitCode -ne 0) {
        throw "The demo manager exited with code $($managerProcess.ExitCode). See $stderrLog."
    }
}
finally {
    if ($null -ne $httpClient) {
        $httpClient.Dispose()
    }
    if ($null -ne $managerProcess) {
        try {
            if (-not $managerProcess.HasExited) {
                # The retained Process object belongs to our own Start-Process
                # invocation. Never look up or stop another process by port/name.
                $managerProcess.Kill()
                [void]$managerProcess.WaitForExit(5000)
            }
        }
        finally {
            $managerProcess.Dispose()
        }
    }
    Write-Host "Demo stopped. Session files were retained: $sessionRoot"
}
