# Data-only regression: never invokes the inert PE fixture, installer, SCM or
# directory-ACL mutator. Works with the existing package-staging test entry point.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$source = Join-Path $PSScriptRoot '../../deploy/windows-rust'
. (Join-Path $source 'Package-Preflight.ps1')
$temporary = Join-Path ([IO.Path]::GetTempPath()) ('tracebolt-preflight-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporary | Out-Null
function Assert([bool]$Condition, [string]$Message) { if (!$Condition) { throw $Message } }
function Write-Checksums([string]$Directory) {
    $lines = @('tracebolt-windows-agent.exe','Install-Tracebolt.ps1','Uninstall-Tracebolt.ps1','Package-Preflight.ps1','README.md') | ForEach-Object {
        '{0}  {1}' -f (Get-FileHash -LiteralPath (Join-Path $Directory $_) -Algorithm SHA256).Hash.ToLowerInvariant(), $_
    }
    [IO.File]::WriteAllText((Join-Path $Directory 'SHA256SUMS.txt'), ($lines -join "`n") + "`n", [Text.Encoding]::ASCII)
}
function New-FixturePackage {
    $root = Join-Path $temporary ([Guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $root | Out-Null
    # Deliberately incomplete/inert PE-shaped bytes, never a runnable program.
    $bytes = New-Object byte[] 512
    $bytes[0] = 0x4d; $bytes[1] = 0x5a; $bytes[0x3c] = 0x80
    $bytes[0x80] = 0x50; $bytes[0x81] = 0x45
    $bytes[0x84] = 0x64; $bytes[0x85] = 0x86
    $bytes[0x94] = 112; $bytes[0x96] = 2
    $bytes[0x98] = 0x0b; $bytes[0x99] = 2
    [IO.File]::WriteAllBytes((Join-Path $root 'tracebolt-windows-agent.exe'), $bytes)
    foreach ($leaf in @('Install-Tracebolt.ps1','Uninstall-Tracebolt.ps1','Package-Preflight.ps1')) {
        Copy-Item -LiteralPath (Join-Path $source $leaf) -Destination (Join-Path $root $leaf)
    }
    [IO.File]::WriteAllText((Join-Path $root 'README.md'), 'inert test package')
    Write-Checksums $root
    return $root
}
function Get-Snapshot([string]$Directory) {
    return (@(Get-ChildItem -LiteralPath $Directory -Recurse -Force | Sort-Object FullName | ForEach-Object {
        $relative = $_.FullName.Substring($Directory.Length)
        if ($_.PSIsContainer) { $relative + ':directory' } else {
            $relative + ':' + [Convert]::ToBase64String([IO.File]::ReadAllBytes($_.FullName))
        }
    }) -join '|')
}
function Assert-RejectedUnchanged([string]$Directory, [string]$Executable) {
    if (!$Executable) { $Executable = Join-Path $Directory 'tracebolt-windows-agent.exe' }
    $before = Get-Snapshot $Directory
    for ($i = 0; $i -lt 2; $i++) {
        $lock = $null; $rejected = $false
        try { $lock = Open-TraceboltPackage $Executable $Directory } catch { $rejected = $true } finally {
            if ($null -ne $lock) { foreach ($stream in $lock.Streams) { $stream.Dispose() } }
        }
        Assert $rejected 'Invalid package was accepted.'
        Assert ((Get-Snapshot $Directory) -ceq $before) 'Package preflight changed files.'
        # A failed check must release every partial lock, including its manifest.
        foreach ($file in Get-ChildItem -LiteralPath $Directory -Recurse -File) {
            $stream = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
            $stream.Dispose()
        }
    }
}
try {
    # Compile only our reviewed interop source; no Win32 method is called here.
    Initialize-TraceboltInstallerType
    $root = New-FixturePackage
    $before = Get-Snapshot $root
    for ($i = 0; $i -lt 2; $i++) {
        $lock = Open-TraceboltPackage (Join-Path $root 'tracebolt-windows-agent.exe') $root
        try {
            Assert ($lock.ExecutableStream.Position -eq 0) 'Verified stream was not rewound.'
            Assert ((Get-TraceboltStreamHash $lock.ExecutableStream) -ceq $lock.SHA256) 'Locked stream digest differs.'
            if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
                foreach ($file in Get-ChildItem -LiteralPath $root -File) {
                    $writer = $null; $denied = $false
                    try { $writer = [IO.File]::Open($file.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite) } catch { $denied = $true } finally {
                        if ($null -ne $writer) { $writer.Dispose() }
                    }
                    Assert $denied 'Verified package allowed an open writer during use.'
                }
                $renamed = "$root-renamed"
                $denied = $false
                try { [IO.Directory]::Move($root, $renamed) } catch { $denied = $true }
                if (!$denied) { [IO.Directory]::Move($renamed, $root) }
                Assert $denied 'Verified package directory was renameable during use.'
                $renamed = Join-Path $root 'renamed.exe'
                $denied = $false
                try { [IO.File]::Move($lock.ExecutablePath, $renamed) } catch { $denied = $true }
                if (!$denied) { [IO.File]::Move($renamed, $lock.ExecutablePath) }
                Assert $denied 'Verified executable was renameable during use.'
            }
        } finally { foreach ($stream in $lock.Streams) { $stream.Dispose() } }
        Assert ((Get-Snapshot $root) -ceq $before) 'Valid repeat preflight changed files.'
    }
    foreach ($case in @('tampered-exe','x86','arm64','dll','dos','pe','bounds','optional','tiny','missing-exe','script','missing-manifest','empty','oversized','encoding','missing-row','duplicate','extra','blank','uppercase','path','outside','foreign-file','foreign-directory')) {
        $root = New-FixturePackage
        $exe = Join-Path $root 'tracebolt-windows-agent.exe'
        $manifest = Join-Path $root 'SHA256SUMS.txt'
        $bytes = [IO.File]::ReadAllBytes($exe)
        $text = [IO.File]::ReadAllText($manifest)
        switch ($case) {
            'tampered-exe' { $bytes[511] = 1; [IO.File]::WriteAllBytes($exe, $bytes) }
            'x86' { $bytes[0x84] = 0x4c; $bytes[0x85] = 1 }
            'arm64' { $bytes[0x84] = 0x64; $bytes[0x85] = 0xaa }
            'dll' { $bytes[0x97] = 0x20 }
            'dos' { $bytes[0] = 0 }
            'pe' { $bytes[0x80] = 0 }
            'bounds' { $bytes[0x3f] = 0x7f }
            'optional' { $bytes[0x95] = 0x7f }
            'tiny' { $bytes = New-Object byte[] 63 }
            'missing-exe' { Remove-Item -LiteralPath $exe }
            'script' { [IO.File]::AppendAllText((Join-Path $root 'Install-Tracebolt.ps1'), '# changed') }
            'missing-manifest' { Remove-Item -LiteralPath $manifest }
            'empty' { [IO.File]::WriteAllText($manifest, '') }
            'oversized' { [IO.File]::WriteAllText($manifest, ('x' * 8193)) }
            'encoding' { [IO.File]::WriteAllBytes($manifest, [byte[]]@(255, 254)) }
            'missing-row' { [IO.File]::WriteAllText($manifest, (($text -split "`n" | Select-Object -Skip 1) -join "`n")) }
            'duplicate' { $lines = $text.TrimEnd().Split("`n"); $lines[1] = $lines[0]; [IO.File]::WriteAllText($manifest, ($lines -join "`n")) }
            'extra' { [IO.File]::AppendAllText($manifest, ('0' * 64) + "  foreign.exe`n") }
            'blank' { [IO.File]::AppendAllText($manifest, "`n") }
            'uppercase' { [IO.File]::WriteAllText($manifest, $text.ToUpperInvariant()) }
            'path' { [IO.File]::WriteAllText($manifest, $text.Replace('README.md', '../README.md')) }
            'outside' { $exe = Join-Path $temporary 'outside.exe'; [IO.File]::WriteAllBytes($exe, $bytes) }
            'foreign-file' { [IO.File]::WriteAllText((Join-Path $root 'foreign.dll'), 'preserve foreign data') }
            'foreign-directory' {
                $foreign = Join-Path $root 'tracebolt-windows-agent.exe.local'
                New-Item -ItemType Directory -Path $foreign | Out-Null
                [IO.File]::WriteAllText((Join-Path $foreign 'foreign.txt'), 'preserve nested foreign data')
            }
        }
        if (@('x86','arm64','dll','dos','pe','bounds','optional','tiny') -contains $case) {
            [IO.File]::WriteAllBytes($exe, $bytes)
            Write-Checksums $root # Correct hash must not authorize wrong PE architecture/shape.
        }
        Assert-RejectedUnchanged $root $exe
    }
    # A directory junction/symlink in the package chain is rejected as data.
    $root = New-FixturePackage
    $link = Join-Path $temporary 'linked-package'
    $kind = if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) { 'Junction' } else { 'SymbolicLink' }
    New-Item -ItemType $kind -Path $link -Target $root | Out-Null
    $rejected = $false
    try { $null = Open-TraceboltPackage (Join-Path $link 'tracebolt-windows-agent.exe') $link } catch { $rejected = $true }
    Assert $rejected 'Linked package parent was accepted.'
    Remove-Item -LiteralPath $link -Force
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        # In-memory descriptors only. Never Set-Acl or the directory mutator.
        function Get-Acl([string]$LiteralPath) { return $script:FixtureAcl }
        try {
            foreach ($case in @('trusted','creator','owner','write','delete','children','dacl','take','null-dacl')) {
                $script:FixtureAcl = [Security.AccessControl.DirectorySecurity]::new()
                $owner = if ($case -ceq 'owner') { 'S-1-5-21-1-2-3-1000' } else { 'S-1-5-18' }
                $script:FixtureAcl.SetOwner([Security.Principal.SecurityIdentifier]::new($owner))
                $script:FixtureAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), 'FullControl', 'Allow'))
                $rights = switch ($case) {
                    'creator' { 'CreateDirectories' }; 'write' { 'WriteData' }; 'delete' { 'Delete' }
                    'children' { 'DeleteSubdirectoriesAndFiles' }; 'dacl' { 'ChangePermissions' }; 'take' { 'TakeOwnership' }
                }
                if ($rights) {
                    $script:FixtureAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                        [Security.Principal.SecurityIdentifier]::new('S-1-5-11'), $rights, 'Allow'))
                }
                if ($case -ceq 'null-dacl') {
                    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new('O:SYG:SYD:NO_ACCESS_CONTROL')
                    $script:NullAclBytes = New-Object byte[] $descriptor.BinaryLength
                    $descriptor.GetBinaryForm($script:NullAclBytes, 0)
                    $script:FixtureAcl = [pscustomobject]@{}
                    $script:FixtureAcl | Add-Member -MemberType ScriptMethod -Name GetSecurityDescriptorBinaryForm -Value { return ,$script:NullAclBytes }
                }
                $rejected = $false
                try { Assert-TraceboltInstallParent $root } catch { $rejected = $true }
                Assert ($rejected -eq (@('trusted','creator') -notcontains $case)) "Unexpected in-memory parent-ACL result: $case"
            }
        } finally { Remove-Item Function:\Get-Acl }
    }
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
Write-Host 'Data-only installer package/hash/architecture preflight regression passed; no native installation acceptance.'
