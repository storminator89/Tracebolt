[CmdletBinding()]
param([string]$OutputDirectory = (Join-Path $PSScriptRoot '../../artifacts/windows-rust'))
$ErrorActionPreference = 'Stop'
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
if ((Test-Path -LiteralPath $OutputDirectory) -or (Test-Path -LiteralPath "$OutputDirectory.zip")) {
    throw 'Package output already exists. Select a new output directory; existing files were not changed.'
}
$crate = Join-Path $PSScriptRoot '../../rust/windows-agent'
Push-Location $crate
try {
    cargo fmt --check
    if ($LASTEXITCODE -ne 0) { throw 'Rust formatting failed.' }
    cargo clippy --locked --target x86_64-pc-windows-msvc --all-targets -- -D warnings
    if ($LASTEXITCODE -ne 0) { throw 'Rust Windows lint failed.' }
    cargo test --locked --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw 'Rust tests failed.' }
    cargo build --locked --release --target x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw 'Windows build failed.' }
    & (Join-Path $PSScriptRoot 'Write-Package.ps1') -Executable (Join-Path $crate 'target/x86_64-pc-windows-msvc/release/tracebolt-windows-agent.exe') -OutputDirectory $OutputDirectory
} finally { Pop-Location }
