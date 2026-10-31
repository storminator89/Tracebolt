# Filesystem-only packaging helper. No enrollment, SCM or host configuration.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Executable,
    [Parameter(Mandatory)][string]$OutputDirectory
)
$ErrorActionPreference = 'Stop'
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
$archive = "$OutputDirectory.zip"
# Never clean, reuse, merge into or replace a caller-owned output path.
if ((Test-Path -LiteralPath $OutputDirectory) -or (Test-Path -LiteralPath $archive)) {
    throw 'Package output already exists. Select a new output directory; existing files were not changed.'
}
$sources = [ordered]@{
    'tracebolt-windows-agent.exe' = $Executable
    'Install-Tracebolt.ps1' = (Join-Path $PSScriptRoot 'Install-Tracebolt.ps1')
    'Uninstall-Tracebolt.ps1' = (Join-Path $PSScriptRoot 'Uninstall-Tracebolt.ps1')
    'README.md' = (Join-Path $PSScriptRoot '../../rust/windows-agent/README.md')
}
foreach ($source in $sources.Values) {
    $item = Get-Item -LiteralPath $source -Force
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Package inputs must be regular files, not directories or links.'
    }
}
$parent = Split-Path $OutputDirectory -Parent
New-Item -ItemType Directory -Path $parent -Force | Out-Null
$stage = Join-Path $parent ('.tracebolt-rust-package-' + [Guid]::NewGuid().ToString('N'))
$stageArchive = "$stage.zip"
try {
    New-Item -ItemType Directory -Path $stage | Out-Null
    foreach ($name in $sources.Keys) {
        Copy-Item -LiteralPath $sources[$name] -Destination (Join-Path $stage $name)
    }
    $checksums = @($sources.Keys | Sort-Object | ForEach-Object {
        $hash = (Get-FileHash -LiteralPath (Join-Path $stage $_) -Algorithm SHA256).Hash.ToLowerInvariant()
        '{0}  {1}' -f $hash, $_
    })
    $checksums | Set-Content -LiteralPath (Join-Path $stage 'SHA256SUMS.txt') -Encoding ascii
    $allowlist = @($sources.Keys) + 'SHA256SUMS.txt'
    # Only these explicit fresh files enter the archive. No recursive wildcard,
    # reused output, stale executable, hidden file or nested directory is input.
    $inputs = @($allowlist | ForEach-Object { Join-Path $stage $_ })
    Compress-Archive -LiteralPath $inputs -DestinationPath $stageArchive
    # The .NET moves refuse destinations that appeared after preflight. Unlike
    # Move-Item to a directory, they cannot merge staging into an existing path.
    [IO.Directory]::Move($stage, $OutputDirectory)
    [IO.File]::Move($stageArchive, $archive)
} finally {
    # Only this invocation's random staging paths can be removed. A complete
    # published directory survives an uncertain archive move for inspection.
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
    if (Test-Path -LiteralPath $stageArchive) { Remove-Item -LiteralPath $stageArchive -Force }
}
