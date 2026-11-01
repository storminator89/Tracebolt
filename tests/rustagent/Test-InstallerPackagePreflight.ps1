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
    foreach ($case in @(
        @('S-1-1-0','everyone'), @('S-1-5-11','authenticated-users'), @('S-1-5-32-545','builtin-users'),
        @('S-1-3-0','creator-owner'), @('S-1-15-2-1','all-app-packages'), @('S-1-15-2-2','restricted-app-packages'),
        @('private-looking-account-token-path','other-principal')
    )) {
        $diagnostic = Format-TraceboltParentAclDiagnostic 'drive-root' $case[0] 2147483647 $true
        Assert ($diagnostic -ceq "INSTALL_PARENT_ACL_UNSAFE parent=drive-root principal=$($case[1]) forbiddenMask=1343029586 inherited=1") 'ACL diagnostic escaped its finite vocabulary.'
        Assert (!$diagnostic.Contains($case[0])) 'ACL diagnostic disclosed a raw principal.'
    }
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
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        # Case-sensitive data fixture: never return a caller spelling that could
        # name a different, unverified file from the literal checked package path.
        $root = New-FixturePackage
        $alias = Join-Path (Split-Path -Parent $root) (Split-Path -Leaf $root).ToUpperInvariant()
        New-Item -ItemType Directory -Path $alias | Out-Null
        $other = Join-Path $alias 'tracebolt-windows-agent.exe'
        [IO.File]::WriteAllText($other, 'inert unverified spelling alias, never executed')
        $lock = Open-TraceboltPackage $other $root
        try { Assert ($lock.ExecutablePath -ceq (Join-Path $root 'tracebolt-windows-agent.exe')) 'Invocation path differed from the literal verified path.' }
        finally { foreach ($stream in $lock.Streams) { $stream.Dispose() } }
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
        # Probe sharing only on our own disposable directory. Request an existing
        # FILE_WRITE_DATA handle but never write, set a reparse point or set ACLs.
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
public static class TraceboltDirectoryLeaseProbe {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
    private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
    public static SafeFileHandle OpenWrite(string path) {
        var handle = CreateFileW(path, 2, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (handle.IsInvalid) { int error=Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
        return handle;
    }
}
'@
        $leaseRoot = Join-Path $temporary 'directory-lease-fixture'
        New-Item -ItemType Directory -Path $leaseRoot | Out-Null
        $writer = [TraceboltDirectoryLeaseProbe]::OpenWrite($leaseRoot)
        try {
            $unexpected = $null; $rejected = $false
            try { $unexpected = [Tracebolt.InstallDirectoryLease]::Acquire([string[]]@($leaseRoot)) } catch {
                $rejected = $_.Exception.InnerException -is [ComponentModel.Win32Exception] -and $_.Exception.InnerException.NativeErrorCode -eq 32
            } finally { if ($null -ne $unexpected) { $unexpected.Dispose() } }
            Assert $rejected 'An existing directory write/reparse-mutation handle did not exclude lease acquisition.'
        } finally { $writer.Dispose() }
        $lease = [Tracebolt.InstallDirectoryLease]::Acquire([string[]]@($leaseRoot))
        try {
            $writer = $null; $rejected = $false
            try { $writer = [TraceboltDirectoryLeaseProbe]::OpenWrite($leaseRoot) } catch {
                $rejected = $_.Exception.InnerException -is [ComponentModel.Win32Exception] -and $_.Exception.InnerException.NativeErrorCode -eq 32
            } finally { if ($null -ne $writer) { $writer.Dispose() } }
            Assert $rejected 'Live directory lease did not deny a write/reparse-mutation handle.'
            $renamed = "$leaseRoot-renamed"
            $rejected = $false
            try { [IO.Directory]::Move($leaseRoot, $renamed) } catch { $rejected = $true }
            if (!$rejected) { [IO.Directory]::Move($renamed, $leaseRoot) }
            Assert $rejected 'Live target directory lease allowed namespace replacement.'
            $child = Join-Path $leaseRoot 'new-child'
            New-Item -ItemType Directory -Path $child | Out-Null
            $lease.Pin($child)
            Assert ($lease.Covers($child)) 'Lease was not extended to a fresh child.'
            Assert (!$lease.HasBoundChild($leaseRoot)) 'Pin/Covers alone incorrectly established relative-create binding.'
            [IO.File]::WriteAllText((Join-Path $child 'foreign.txt'), 'ordinary child creation remains possible; preserve data')
        } finally { $lease.Dispose() }
        Assert (!$lease.Covers($leaseRoot)) 'Released handles still grant target admission.'
        $writer = [TraceboltDirectoryLeaseProbe]::OpenWrite($leaseRoot)
        $writer.Dispose()
        [IO.Directory]::Move($leaseRoot, "$leaseRoot-released")
        [IO.Directory]::Move("$leaseRoot-released", $leaseRoot)
        # In-memory descriptors only. Never Set-Acl or the directory mutator.
        $script:FixtureAclTarget = $null
        function Get-Acl([string]$LiteralPath) {
            if ($script:FixtureAclTarget -and $LiteralPath -cne $script:FixtureAclTarget) { return $script:AncestorAcl }
            return $script:FixtureAcl
        }
        try {
            foreach ($case in @('trusted','creator','owner','write','attributes','extended','delete','children','dacl','take','null-dacl')) {
                $script:FixtureAcl = [Security.AccessControl.DirectorySecurity]::new()
                $owner = if ($case -ceq 'owner') { 'S-1-5-21-1-2-3-1000' } else { 'S-1-5-18' }
                $script:FixtureAcl.SetOwner([Security.Principal.SecurityIdentifier]::new($owner))
                $script:FixtureAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
                    [Security.Principal.SecurityIdentifier]::new('S-1-5-18'), 'FullControl', 'Allow'))
                $rights = switch ($case) {
                    'creator' { 'CreateDirectories' }; 'write' { 'WriteData' }; 'delete' { 'Delete' }
                    'attributes' { 'WriteAttributes' }; 'extended' { 'WriteExtendedAttributes' }
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
                $rejected = $false; $message = ''
                # PowerShell wraps the C# IOException in MethodInvocationException;
                # compare the unchanged finite cause, not the invocation envelope.
                try { Assert-TraceboltInstallParent $root } catch { $rejected = $true; $message = $_.Exception.GetBaseException().Message }
                Assert ($rejected -eq (@('trusted','creator') -notcontains $case)) "Unexpected in-memory parent-ACL result: $case"
                if (@('write','attributes','extended','delete','children','dacl','take') -contains $case) {
                    $mask = switch ($case) { 'write' { 2 }; 'attributes' { 256 }; 'extended' { 16 }; 'delete' { 65536 }; 'children' { 64 }; 'dacl' { 262144 }; 'take' { 524288 } }
                    Assert ($message -ceq "INSTALL_PARENT_ACL_UNSAFE parent=other-ancestor principal=authenticated-users forbiddenMask=$mask inherited=0") 'Unsafe ACL diagnostic did not preserve the exact finite cause.'
                    Assert (!$message.Contains($root)) 'ACL diagnostic disclosed a private path.'
                }
            }
            # Preserve raw generic bits: public FileSystemAccessRule constructors
            # reject these masks; in-memory SDDL must prove the actual parser path.
            foreach ($case in @(
                @('GA','',268435456,$true), @('GW','',1073741824,$true),
                @('GA','CI',268435456,$true), @('GW','ID',1073741824,$true),
                @('GA','CIIO',268435456,$false), @('GW','CIIO',1073741824,$false),
                @('GR','',2147483648,$false), @('GX','',536870912,$false),
                @('GA','',268435456,$false,'D','AU'), @('GW','',1073741824,$false,'D','AU'),
                @('GA','',268435456,$false,'A','BA'), @('GW','',1073741824,$false,'A','BA')
            )) {
                $aceType = if ($case.Count -gt 4) { $case[4] } else { 'A' }
                $principal = if ($case.Count -gt 5) { $case[5] } else { 'AU' }
                $sid = if ($principal -ceq 'BA') { 'S-1-5-32-544' } else { 'S-1-5-11' }
                $script:FixtureAcl = [Security.AccessControl.DirectorySecurity]::new()
                $script:FixtureAcl.SetSecurityDescriptorSddlForm("O:SYG:SYD:P(A;;FA;;;SY)($aceType;$($case[1]);$($case[0]);;;$principal)")
                $rawRule = @($script:FixtureAcl.GetAccessRules($true,$true,[Security.Principal.SecurityIdentifier]) | Where-Object { $_.IdentityReference.Value -ceq $sid })[0]
                Assert ((([long][int]$rawRule.FileSystemRights -band 0xffffffff) -band $case[2]) -eq $case[2]) 'Generic fixture lost its intended raw rights.'
                $rejected = $false; $message = ''
                try { Assert-TraceboltInstallParent $root } catch { $rejected = $true; $message = $_.Exception.GetBaseException().Message }
                Assert ($rejected -eq $case[3]) "Generic ACE decision changed: $($case[0])/$($case[1])"
                if ($case[3]) { Assert ($message -match "forbiddenMask=$($case[2]) ") 'Rejected generic rights were hidden by diagnostics.' }
            }
            # Pure descriptor classification only: synthetic bytes cannot grant
            # native lease state, path trust, or permission to stage a child.
            $programData = [Environment]::GetFolderPath('CommonApplicationData')
            function Assert-AclClassification([string]$Sddl, [string]$Path, [string]$Expected) {
                $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($Sddl)
                $bytes = New-Object byte[] $descriptor.BinaryLength
                $descriptor.GetBinaryForm($bytes, 0)
                $rejected = $false; $result = $null
                try { $result = [Tracebolt.InstallDirectoryLease]::EvaluateAclForFixture($bytes, $Path) }
                catch { $rejected = $true }
                if ($Expected -ceq 'reject') {
                    Assert $rejected 'Synthetic descriptor classification unexpectedly admitted an unsafe ACL.'
                } else {
                    Assert (!$rejected -and $result -ceq $Expected) 'Synthetic descriptor classification mismatch.'
                }
            }
            $prefix = 'O:SYG:SYD:P(A;;FA;;;SY)'
            Assert-AclClassification $prefix $programData 'strict'
            foreach ($rights in @('0x2','0x112')) {
                Assert-AclClassification ($prefix + "(A;;$rights;;;BU)") $programData 'relative-child-required'
                Assert-AclClassification ($prefix + "(A;;$rights;;;BU)") $root 'reject'
                Assert-AclClassification ($prefix + "(A;;$rights;;;AU)") $programData 'reject'
            }
            foreach ($rights in @('0x10002','0x42','0x40002','0x80002','0x102','0x12','0x100','0x10','0x110','GA','GW',
                '0x10112','0x152','0x40112','0x80112','0x10000112','0x40000112','0x02000112','0x02000000')) {
                Assert-AclClassification ($prefix + "(A;;$rights;;;BU)") $programData 'reject'
            }
            Assert-AclClassification 'O:S-1-5-21-1-2-3-1000G:SYD:P(A;;0x112;;;BU)' $programData 'reject'
            Assert-AclClassification 'O:SYG:SYD:NO_ACCESS_CONTROL' $programData 'reject'
            # No combining separate grants into the reviewed exact ACE tuple.
            Assert-AclClassification ($prefix + '(A;;0x2;;;BU)(A;;0x110;;;BU)') $programData 'reject'
            Assert-AclClassification ($prefix + '(A;;0x2;;;BU)(A;;0x112;;;BU)') $programData 'relative-child-required'
            # Deny and inherit-only entries grant nothing, but never cancel an
            # independently unsafe applicable allow ACE.
            Assert-AclClassification ($prefix + '(D;;GA;;;BU)') $programData 'strict'
            Assert-AclClassification ($prefix + '(A;CIIO;GA;;;BU)') $programData 'strict'
            Assert-AclClassification ($prefix + '(D;;GA;;;BU)(A;;0x112;;;BU)') $programData 'relative-child-required'
            Assert-AclClassification ($prefix + '(D;;GA;;;BU)(A;;0x100;;;BU)') $programData 'reject'
            Assert-AclClassification ($prefix + '(A;CIIO;GA;;;BU)(A;;0x100;;;BU)') $programData 'reject'
            foreach ($form in @('callback','object','unknown')) {
                $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($prefix)
                $sid = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-545')
                if ($form -ceq 'callback') {
                    $ace = [Security.AccessControl.CommonAce]::new(
                        [Security.AccessControl.AceFlags]::None,
                        [Security.AccessControl.AceQualifier]::AccessAllowed, 274, $sid, $true, [byte[]]@())
                } elseif ($form -ceq 'object') {
                    $ace = [Security.AccessControl.ObjectAce]::new(
                        [Security.AccessControl.AceFlags]::None,
                        [Security.AccessControl.AceQualifier]::AccessAllowed, 274, $sid,
                        [Security.AccessControl.ObjectAceFlags]::None, [Guid]::Empty, [Guid]::Empty, $false, [byte[]]@())
                } else {
                    # Preserve an intentionally unknown wire value as data;
                    # PowerShell's direct enum cast rejects it before the test.
                    $unknownType = [Enum]::ToObject([Security.AccessControl.AceType], [byte]66)
                    $ace = [Security.AccessControl.CustomAce]::new(
                        $unknownType, [Security.AccessControl.AceFlags]::None, [byte[]]@(0,0,0,0))
                }
                $acl = [Security.AccessControl.RawAcl]::new(4, 2)
                $acl.InsertAce(0, $descriptor.DiscretionaryAcl[0]); $acl.InsertAce(1, $ace)
                $descriptor.DiscretionaryAcl = $acl
                $bytes = New-Object byte[] $descriptor.BinaryLength
                $descriptor.GetBinaryForm($bytes, 0)
                $rejected = $false
                try { $null = [Tracebolt.InstallDirectoryLease]::EvaluateAclForFixture($bytes, $programData) }
                catch { $rejected = $true }
                Assert $rejected 'Nonstandard applicable allow ACE was classified as eligible.'
            }
            Write-Host 'INSTALL_PARENT_SYNTHETIC_CLASSIFICATION_ONLY_PASS'
        } finally { Remove-Item Function:\Get-Acl }
        # Real owner/DACL review uses held handles, with no mocked Get-Acl. This
        # only establishes eligibility; no native child, ACL, or host setting changes.
        $lease = $null; $unrelated = $null
        try {
            $lease = [Tracebolt.InstallDirectoryLease]::Acquire([string[]]@($programData))
            $unrelated = [Tracebolt.InstallDirectoryLease]::Acquire([string[]]@($root))
            Assert ($lease.Covers($programData)) 'Live target lease lacks exact handle coverage.'
            Assert (!$unrelated.Covers($programData)) 'Unrelated lease claims target handle coverage.'
            Assert-TraceboltInstallParent $programData $lease
            Assert (!$lease.HasBoundChild($programData)) 'Eligibility review was confused with bound-child proof.'
            $rejected = $false
            try { $lease.RequireBoundChild((Join-Path $programData 'TraceboltRust')) } catch { $rejected = $true }
            Assert $rejected 'Eligibility review granted an uncreated child path gate.'
            $rejected = $false
            try { Assert-TraceboltInstallParent $programData $unrelated } catch { $rejected = $true }
            Assert $rejected 'Real ProgramData review admitted an unrelated native lease.'
            foreach ($invalid in @($null, @{Covers=$true})) {
                $rejected = $false; $neverCreated = Join-Path $temporary 'must-require-native-lease'
                try { New-TraceboltProtectedDirectory $neverCreated $invalid } catch { $rejected = $true }
                Assert ($rejected -and !(Test-Path -LiteralPath $neverCreated)) 'Missing or forged lease reached protected creation.'
            }
            $lease.Dispose()
            Assert (!$lease.Covers($programData) -and !$lease.HasBoundChild($programData)) 'Disposed lease retained native proof.'
            $rejected = $false
            try { Assert-TraceboltInstallParent $programData $lease } catch { $rejected = $true }
            Assert $rejected 'Disposed lease admitted real ProgramData review.'
            Write-Host 'INSTALL_PARENT_NATIVE_READONLY_ELIGIBILITY_ONLY_PASS'
        } finally {
            if ($null -ne $lease) { $lease.Dispose() }
            if ($null -ne $unrelated) { $unrelated.Dispose() }
        }
    }
} finally {
    Remove-Item -LiteralPath $temporary -Recurse -Force
}
Write-Host 'Data-only installer package/hash/architecture preflight regression passed; no native installation acceptance.'
