[CmdletBinding()]
param([string]$OutputDirectory = (Join-Path $PSScriptRoot '../../artifacts/windows-rust'))
$ErrorActionPreference = 'Stop'
$crate = Join-Path $PSScriptRoot '../../rust/windows-agent'
Push-Location $crate
try {
    cargo test --locked
    if ($LASTEXITCODE -ne 0) { throw 'Rust tests failed.' }
    cargo build --locked --release --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw 'Windows build failed.' }
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    Copy-Item 'target/x86_64-pc-windows-msvc/release/tracebolt-windows-agent.exe' $OutputDirectory
    Copy-Item (Join-Path $PSScriptRoot 'Install-Tracebolt.ps1'),(Join-Path $PSScriptRoot 'Uninstall-Tracebolt.ps1'),(Join-Path $crate 'README.md') $OutputDirectory
    Get-ChildItem $OutputDirectory -File | Where-Object Name -ne 'SHA256SUMS.txt' | Get-FileHash -Algorithm SHA256 | ForEach-Object { '{0}  {1}' -f $_.Hash.ToLowerInvariant(),(Split-Path $_.Path -Leaf) } | Set-Content (Join-Path $OutputDirectory 'SHA256SUMS.txt') -Encoding ascii
    Compress-Archive -Path (Join-Path $OutputDirectory '*') -DestinationPath "$OutputDirectory.zip" -Force
} finally { Pop-Location }
