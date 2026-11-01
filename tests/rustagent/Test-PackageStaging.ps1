# Portable filesystem regression only. No native executable or installer is run.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$package = Join-Path $PSScriptRoot '../../deploy/windows-rust/Write-Package.ps1'
$builder = Join-Path $PSScriptRoot '../../deploy/windows-rust/Build-Package.ps1'
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('tracebolt-package-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
function Assert([bool]$Condition, [string]$Message) {
    if (!$Condition) { throw $Message }
}
try {
    foreach ($leaf in @('Install-Tracebolt.ps1','Uninstall-Tracebolt.ps1','Package-Preflight.ps1','Write-Package.ps1','Build-Package.ps1')) {
        $tokens = $null; $errors = $null
        $null = [Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path $package -Parent) $leaf), [ref]$tokens, [ref]$errors)
        Assert ($errors.Count -eq 0) "PowerShell source parse failed: $leaf"
    }
    $executable = Join-Path $temporary 'synthetic-input.exe'
    [IO.File]::WriteAllText($executable, 'inert packaging fixture, not an executable')
    $existing = Join-Path $temporary 'existing'
    New-Item -ItemType Directory -Path (Join-Path $existing 'nested') -Force | Out-Null
    $foreign = Join-Path $existing 'nested/foreign.txt'
    [IO.File]::WriteAllText($foreign, 'preserve unrelated file')
    $rejected = $false
    try { & $package -Executable $executable -OutputDirectory $existing } catch { $rejected = $true }
    Assert $rejected 'Existing output directory was accepted.'
    Assert ([IO.File]::ReadAllText($foreign) -eq 'preserve unrelated file') 'Existing output was changed.'
    Assert (!(Test-Path -LiteralPath "$existing.zip")) 'Rejected directory produced an archive.'
    $message = ''
    try { & $builder -OutputDirectory $existing } catch { $message = $_.Exception.Message }
    Assert ($message -like 'Package output already exists.*') 'Builder did not reject reused output before running Cargo.'
    Assert ([IO.File]::ReadAllText($foreign) -eq 'preserve unrelated file') 'Builder changed existing output.'

    $output = Join-Path $temporary 'fresh'
    & $package -Executable $executable -OutputDirectory $output
    $expected = @('Install-Tracebolt.ps1','Package-Preflight.ps1','README.md','SHA256SUMS.txt','Uninstall-Tracebolt.ps1','tracebolt-windows-agent.exe') | Sort-Object
    $actual = @(Get-ChildItem -LiteralPath $output -Recurse -File | ForEach-Object { $_.Name } | Sort-Object)
    Assert (($actual -join '|') -ceq ($expected -join '|')) 'Staging did not contain the exact allowlist.'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [IO.Compression.ZipFile]::OpenRead("$output.zip")
    try {
        $names = @($zip.Entries | ForEach-Object { $_.FullName } | Sort-Object)
        Assert (($names -join '|') -ceq ($expected -join '|')) 'ZIP contains unexpected, nested or missing entries.'
        foreach ($entry in $zip.Entries) {
            $stream = $entry.Open()
            $memory = New-Object IO.MemoryStream
            try {
                $stream.CopyTo($memory)
                $actualBytes = $memory.ToArray()
                $expectedBytes = [IO.File]::ReadAllBytes((Join-Path $output $entry.FullName))
                Assert ([Convert]::ToBase64String($actualBytes) -ceq [Convert]::ToBase64String($expectedBytes)) 'ZIP bytes differ from staging.'
            } finally { $stream.Dispose(); $memory.Dispose() }
        }
    } finally { $zip.Dispose() }
    $lines = @(Get-Content -LiteralPath (Join-Path $output 'SHA256SUMS.txt'))
    Assert ($lines.Count -eq 5) 'Each allowlisted payload needs exactly one checksum.'
    foreach ($line in $lines) {
        Assert ($line -cmatch '^([a-f0-9]{64})  ([^/\\]+)$') 'Invalid checksum row.'
        $hash = (Get-FileHash -LiteralPath (Join-Path $output $Matches[2]) -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert ($hash -ceq $Matches[1]) 'Checksum does not bind the packaged bytes.'
    }

    $archiveOnly = Join-Path $temporary 'archive-only'
    [IO.File]::WriteAllText("$archiveOnly.zip", 'preserve existing archive')
    $rejected = $false
    try { & $package -Executable $executable -OutputDirectory $archiveOnly } catch { $rejected = $true }
    Assert $rejected 'Existing archive was replaced.'
    Assert ([IO.File]::ReadAllText("$archiveOnly.zip") -eq 'preserve existing archive') 'Existing archive bytes changed.'
    Assert (!(Test-Path -LiteralPath $archiveOnly)) 'Rejected archive produced a directory.'
    Assert (@(Get-ChildItem -LiteralPath $temporary -Force | Where-Object Name -Like '.tracebolt-rust-package-*').Count -eq 0) 'Temporary staging leaked.'
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
Write-Host 'Filesystem-only package staging and checksum regression passed.'
& (Join-Path $PSScriptRoot 'Test-InstallerPackagePreflight.ps1')
