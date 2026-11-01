# Native fixtures mutate only new random children of one owned TEMP directory.
# No installer, binary, service, or privilege adjustment is invoked; no existing ACL is modified.
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot '../../deploy/windows-rust/Package-Preflight.ps1')
Initialize-TraceboltInstallerType
if (-not ('Tracebolt.RelativeDirectoryFixture' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Tracebolt {
    // Test-only mount-point writer: callers supply exclusively their own TEMP children.
    public sealed class RelativeDirectoryFixture : IDisposable {
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern SafeFileHandle CreateFileW(string p, uint access, uint share,
            IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool DeviceIoControl(SafeFileHandle h, uint code, byte[] input,
            uint length, IntPtr output, uint outputLength, out uint returned, IntPtr overlapped);
        public static SafeFileHandle Open(string path, uint access) {
            SafeFileHandle h = CreateFileW(path, access, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
            if (h.IsInvalid) { h.Dispose(); return null; }
            return h;
        }
        readonly SafeFileHandle mutator;
        readonly byte[] mount;
        readonly ManualResetEvent stop = new ManualResetEvent(false);
        readonly ManualResetEvent started = new ManualResetEvent(false);
        Thread worker;
        public int SuccessfulSets;
        public bool CheckpointEntered;
        public Action BeforeNativeCheckpoint() {
            return delegate() {
                CheckpointEntered = true;
                if (!Set()) throw new InvalidOperationException("RELATIVE_CHECKPOINT_SET_FAILED");
            };
        }
        public bool WorkerFailed;
        public RelativeDirectoryFixture(SafeFileHandle handle, string target) {
            mutator = handle;
            byte[] sub = Encoding.Unicode.GetBytes(@"\??\" + target);
            byte[] print = Encoding.Unicode.GetBytes(target);
            mount = new byte[16 + sub.Length + 2 + print.Length + 2];
            Buffer.BlockCopy(BitConverter.GetBytes(0xA0000003u), 0, mount, 0, 4);
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)(mount.Length - 8)), 0, mount, 4, 2);
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)sub.Length), 0, mount, 10, 2);
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)(sub.Length + 2)), 0, mount, 12, 2);
            Buffer.BlockCopy(BitConverter.GetBytes((ushort)print.Length), 0, mount, 14, 2);
            Buffer.BlockCopy(sub, 0, mount, 16, sub.Length);
            Buffer.BlockCopy(print, 0, mount, 18 + sub.Length, print.Length);
        }
        public bool Set() {
            uint n;
            bool ok = DeviceIoControl(mutator, 0x900A4, mount, (uint)mount.Length, IntPtr.Zero, 0, out n, IntPtr.Zero);
            if (ok) Interlocked.Increment(ref SuccessfulSets);
            return ok;
        }
        public bool Clear() {
            byte[] b = new byte[8];
            Buffer.BlockCopy(BitConverter.GetBytes(0xA0000003u), 0, b, 0, 4);
            uint n;
            return DeviceIoControl(mutator, 0x900AC, b, 8, IntPtr.Zero, 0, out n, IntPtr.Zero);
        }
        public void Start() {
            worker = new Thread(delegate() {
                try {
                    for (int i = 0; i < 128 && !stop.WaitOne(0); i++) {
                        Set(); started.Set();
                        if (stop.WaitOne(2)) break;
                        Clear();
                        if (stop.WaitOne(2)) break;
                    }
                } catch { WorkerFailed = true; }
                finally { started.Set(); }
            });
            worker.IsBackground = true; worker.Start();
            if (!started.WaitOne(3000)) throw new InvalidOperationException("RELATIVE_RACE_START_TIMEOUT");
        }
        public void Stop() {
            stop.Set();
            // Only synchronous local filesystem calls; do not delete anything until joined.
            if (worker != null && !worker.Join(5000))
                throw new InvalidOperationException("RELATIVE_RACE_JOIN_TIMEOUT");
        }
        public void Dispose() {
            Stop(); stop.Dispose(); started.Dispose();
            // Handle lifetime belongs to the caller, after reparse restoration.
        }
    }
}
'@
}
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    Write-Host 'RELATIVE_DIRECTORY_HELPER_COMPILE_PASS NATIVE_WINDOWS_SKIP'
    return
}
function Assert-Relative([bool]$Value, [string]$Category) {
    if (!$Value) { throw $Category }
}
function Invoke-RelativeAttempt($ParentHandle, [Action]$BeforeNative = $null) {
    $created = $null
    try {
        if ($null -eq $BeforeNative) {
            $created = [Tracebolt.RustInstallerPath]::CreateRelativeDirectory($ParentHandle, 'state')
        } else {
            # Test-only reflection into the private checkpoint. Public production
            # calls always pass null; this action touches only our own TEMP parent.
            $core = [Tracebolt.RustInstallerPath].GetMethod('CreateRelativeDirectoryCore',
                [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static,
                $null, [type[]]@([Microsoft.Win32.SafeHandles.SafeFileHandle], [string], [Action]), $null)
            Assert-Relative ($null -ne $core) 'RELATIVE_CHECKPOINT_CORE_MISSING'
            $created = $core.Invoke($null, [object[]]@($ParentHandle, 'state', $BeforeNative))
        }
        Assert-Relative ($null -ne $created -and !$created.IsInvalid) 'RELATIVE_INVALID_RESULT'
        return $true
    } catch { return $false }
    finally { if ($null -ne $created) { $created.Dispose() } }
}
function Get-FixtureAcl([string]$Path) {
    return (Get-Acl -LiteralPath $Path).Sddl
}
$root = Join-Path ([IO.Path]::GetTempPath()) ('tracebolt-relative-' + [Guid]::NewGuid().ToString('N'))
$cleanupSafe = $true
[IO.Directory]::CreateDirectory($root) | Out-Null
function New-RelativeParent {
    $p = Join-Path $root ([Guid]::NewGuid().ToString('N'))
    [IO.Directory]::CreateDirectory($p) | Out-Null
    return $p
}
try {
    $p = New-RelativeParent
    $h = [Tracebolt.RustInstallerPath]::Open($p, $true)
    try {
        $createdHandle = $null; $actualHandle = $null
        try {
            $createdHandle = [Tracebolt.RustInstallerPath]::CreateRelativeDirectory($h, 'state')
            $actualHandle = [Tracebolt.RustInstallerPath]::Open((Join-Path $p 'state'), $true)
            Assert-Relative ([Tracebolt.RustInstallerPath]::SameDirectoryObject($createdHandle, $actualHandle)) 'RELATIVE_POSITIVE_IDENTITY_MISMATCH'
            Assert-Relative ([Tracebolt.RustInstallerPath]::FinalDirectoryPath($createdHandle) -ceq [Tracebolt.RustInstallerPath]::FinalDirectoryPath($actualHandle)) 'RELATIVE_POSITIVE_FINAL_PATH_MISMATCH'
        } finally {
            if ($null -ne $actualHandle) { $actualHandle.Dispose() }
            if ($null -ne $createdHandle) { $createdHandle.Dispose() }
        }
        Assert-Relative ([IO.Directory]::Exists((Join-Path $p 'state'))) 'RELATIVE_POSITIVE_MISSING'
        foreach ($leaf in @('', '.', '..', 'other', 'state\child', 'state/child', 'C:\state', 'state:stream')) {
            $accepted = $false; $bad = $null
            try { $bad = [Tracebolt.RustInstallerPath]::CreateRelativeDirectory($h, $leaf); $accepted = $true }
            catch { }
            finally { if ($null -ne $bad) { $bad.Dispose() } }
            Assert-Relative (!$accepted) 'RELATIVE_LEAF_ACCEPTED'
        }
    } finally { $h.Dispose() }
    Write-Host 'RELATIVE_POSITIVE_AND_FIXED_LEAF_PASS'

    $p = New-RelativeParent; $unrelated = New-RelativeParent
    $child = Join-Path $p 'state'; $otherChild = Join-Path $unrelated 'state'
    $lease = [Tracebolt.InstallDirectoryLease]::Acquire([string[]]@($p))
    try {
        $lease.CreateProtectedChild($child)
        Assert-Relative ($lease.Covers($child) -and $lease.HasBoundChild($p)) 'RELATIVE_LEASE_CHILD_NOT_BOUND'
        $renamed = $false
        try { [IO.Directory]::Move($child, (Join-Path $p 'renamed')); $renamed = $true } catch { }
        Assert-Relative (!$renamed -and [IO.Directory]::Exists($child)) 'RELATIVE_LEASE_RENAME_NOT_BLOCKED'
        $accepted = $false
        try { $lease.CreateProtectedChild($otherChild); $accepted = $true } catch { }
        Assert-Relative (!$accepted -and ![IO.Directory]::Exists($otherChild)) 'RELATIVE_UNRELATED_PARENT_ACCEPTED'
        Assert-Relative (@([IO.Directory]::EnumerateFileSystemEntries($unrelated)).Count -eq 0) 'RELATIVE_UNRELATED_PARENT_CHANGED'
    } finally { $lease.Dispose() }
    Assert-Relative (!$lease.Covers($p) -and !$lease.Covers($child) -and !$lease.HasBoundChild($p)) 'RELATIVE_DISPOSED_LEASE_COVERS'
    $disposedChild = Join-Path $p 'TraceboltRust'; $accepted = $false
    try { $lease.CreateProtectedChild($disposedChild); $accepted = $true } catch { }
    Assert-Relative (!$accepted -and ![IO.Directory]::Exists($disposedChild)) 'RELATIVE_DISPOSED_LEASE_ACCEPTED'
    $p = New-RelativeParent
    $h = [Tracebolt.RustInstallerPath]::Open($p, $true); $h.Dispose()
    Assert-Relative (!(Invoke-RelativeAttempt $h)) 'RELATIVE_DISPOSED_PARENT_ACCEPTED'
    Assert-Relative (@([IO.Directory]::EnumerateFileSystemEntries($p)).Count -eq 0) 'RELATIVE_DISPOSED_PARENT_CHANGED'
    Write-Host 'RELATIVE_LEASE_BINDING_RENAME_AND_DISPOSAL_PASS'

    foreach ($kind in @('file', 'directory')) {
        $p = New-RelativeParent; $child = Join-Path $p 'state'
        if ($kind -eq 'directory') {
            [IO.Directory]::CreateDirectory($child) | Out-Null
            $payload = Join-Path $child 'sentinel'
        } else { $payload = $child }
        [IO.File]::WriteAllBytes($payload, [byte[]](0,1,127,128,255))
        $acl = Get-FixtureAcl $child; $parentAcl = Get-FixtureAcl $p
        $payloadAcl = Get-FixtureAcl $payload
        $h = [Tracebolt.RustInstallerPath]::Open($p, $true)
        try { Assert-Relative (!(Invoke-RelativeAttempt $h)) 'RELATIVE_COLLISION_ACCEPTED' }
        finally { $h.Dispose() }
        Assert-Relative (([Convert]::ToBase64String([IO.File]::ReadAllBytes($payload))) -ceq 'AAF/gP8=') 'RELATIVE_COLLISION_BYTES_CHANGED'
        Assert-Relative ((Get-FixtureAcl $child) -ceq $acl) 'RELATIVE_COLLISION_ACL_CHANGED'
        Assert-Relative ((Get-FixtureAcl $p) -ceq $parentAcl) 'RELATIVE_COLLISION_PARENT_CHANGED'
        Assert-Relative ((Get-FixtureAcl $payload) -ceq $payloadAcl) 'RELATIVE_COLLISION_PAYLOAD_ACL_CHANGED'
        Assert-Relative (@([IO.Directory]::EnumerateFileSystemEntries($p)).Count -eq 1) 'RELATIVE_COLLISION_PARENT_CONTENT_CHANGED'
        if ($kind -eq 'directory') {
            Assert-Relative (@([IO.Directory]::EnumerateFileSystemEntries($child)).Count -eq 1) 'RELATIVE_COLLISION_CONTENT_CHANGED'
        }
    }
    Write-Host 'RELATIVE_COLLISION_PRESERVATION_PASS'

    $p = New-RelativeParent
    $h = [Tracebolt.RustInstallerPath]::Open($p, $true)
    try {
        foreach ($access in @([uint32]0x100, [uint32]0x10)) {
            $probe = [Tracebolt.RelativeDirectoryFixture]::Open($p, $access)
            Assert-Relative ($null -ne $probe) 'RELATIVE_ATTRIBUTE_OPEN_UNAVAILABLE'
            $probe.Dispose()
        }
        $probe = [Tracebolt.RelativeDirectoryFixture]::Open($p, [uint32]2)
        try { Assert-Relative ($null -eq $probe) 'RELATIVE_WRITE_DATA_NOT_BLOCKED' }
        finally { if ($null -ne $probe) { $probe.Dispose() } }
    } finally { $h.Dispose() }
    Write-Host 'RELATIVE_READ_LEASE_ATTRIBUTE_EA_OPEN_WRITE_DATA_BLOCKED_PASS'

    # Baseline uses a loose read-only parent + write-data mutator. Attribute-only
    # variants retain the actual production read/shareRead parent lease.
    foreach ($variant in @('prechanged-data', 'checkpoint-data', 'racing-data', 'prechanged-attributes', 'checkpoint-attributes', 'racing-attributes')) {
        $p = New-RelativeParent; $outside = New-RelativeParent
        $h = $null; $mutator = $null; $fixture = $null; $joined = $true
        $supported = $false; $created = $false
        try {
            if ($variant -in @('prechanged-data', 'checkpoint-data', 'racing-data')) {
                $h = [Tracebolt.RelativeDirectoryFixture]::Open($p, [uint32]2147483648)
                $mutator = [Tracebolt.RelativeDirectoryFixture]::Open($p, [uint32]2)
            } else {
                $h = [Tracebolt.RustInstallerPath]::Open($p, $true)
                $mutator = [Tracebolt.RelativeDirectoryFixture]::Open($p, [uint32]0x100)
            }
            Assert-Relative ($null -ne $h -and $null -ne $mutator) 'RELATIVE_FIXTURE_HANDLES_UNAVAILABLE'
            $fixture = [Tracebolt.RelativeDirectoryFixture]::new($mutator, $outside)
            $supported = $fixture.Set()
            if ($variant -in @('prechanged-data', 'checkpoint-data', 'racing-data')) {
                Assert-Relative $supported 'RELATIVE_BASELINE_REPARSE_UNAVAILABLE'
            }
            if ($supported) {
                if ($variant -in @('racing-data', 'racing-attributes')) {
                    Assert-Relative ($fixture.Clear()) 'RELATIVE_RACE_INITIAL_CLEAR_FAILED'
                    $joined = $false; $fixture.Start()
                }
                $checkpoint = $null
                if ($variant -in @('checkpoint-data', 'checkpoint-attributes')) {
                    Assert-Relative ($fixture.Clear()) 'RELATIVE_CHECKPOINT_INITIAL_CLEAR_FAILED'
                    $checkpoint = $fixture.BeforeNativeCheckpoint()
                }
                # Bounded sampling only, not an exhaustive race proof. Retry
                # refusal while the independent toggler is active; stop on create.
                $attemptLimit = 1
                if ($variant -in @('racing-data', 'racing-attributes')) { $attemptLimit = 64 }
                for ($attempt = 0; $attempt -lt $attemptLimit; $attempt++) {
                    $created = Invoke-RelativeAttempt $h $checkpoint
                    if ($created) { break }
                    if ($attemptLimit -gt 1) { Start-Sleep -Milliseconds 2 }
                }
            }
        } finally {
            if ($null -ne $fixture) {
                try { $fixture.Stop(); $joined = $true }
                finally { if (!$joined) { $cleanupSafe = $false } }
            }
            # A failed join deliberately leaves owned TEMP objects rather than
            # racing cleanup against a worker or following a still-live junction.
            if ($joined) {
                try {
                    if ($null -ne $fixture) { [void]$fixture.Clear() }
                    Assert-Relative (([IO.File]::GetAttributes($p) -band [IO.FileAttributes]::ReparsePoint) -eq 0) 'RELATIVE_REPARSE_RESTORE_FAILED'
                } catch { $cleanupSafe = $false; throw }
                finally {
                    if ($null -ne $fixture) { $fixture.Dispose() }
                    if ($null -ne $mutator) { $mutator.Dispose() }
                    if ($null -ne $h) { $h.Dispose() }
                    Assert-Relative (@([IO.Directory]::EnumerateFileSystemEntries($outside)).Count -eq 0) 'RELATIVE_REDIRECTION_TARGET_CHANGED'
                }
            }
        }
        if ($supported) {
            if ($variant -in @('checkpoint-data', 'checkpoint-attributes')) {
                Assert-Relative ($fixture.CheckpointEntered -and $fixture.SuccessfulSets -ge 2) 'RELATIVE_CHECKPOINT_NOT_EXERCISED'
            }
            Assert-Relative (!$fixture.WorkerFailed) 'RELATIVE_RACE_WORKER_FAILED'
            Assert-Relative (!$created -or [IO.Directory]::Exists((Join-Path $p 'state'))) 'RELATIVE_NOT_ORIGINAL_PARENT'
            if ($variant -eq 'prechanged-data') { Write-Host 'RELATIVE_PRECHANGED_READONLY_ROOT_OR_REFUSAL_PASS' }
            elseif ($variant -eq 'checkpoint-data') { Write-Host 'RELATIVE_DATA_NATIVE_EDGE_ORIGINAL_ROOT_OR_REFUSAL_PASS' }
            elseif ($variant -eq 'checkpoint-attributes') { Write-Host 'RELATIVE_ATTRIBUTE_NATIVE_EDGE_ORIGINAL_ROOT_OR_REFUSAL_PASS' }
            elseif ($variant -eq 'racing-data') { Write-Host 'RELATIVE_BOUNDED_DATA_FLIP_SAMPLING_ORIGINAL_ROOT_OR_REFUSAL_PASS' }
            elseif ($variant -eq 'prechanged-attributes') { Write-Host 'RELATIVE_ATTRIBUTE_PRECHANGED_ROOT_OR_REFUSAL_PASS' }
            else { Write-Host 'RELATIVE_BOUNDED_ATTRIBUTE_FLIP_SAMPLING_ORIGINAL_ROOT_OR_REFUSAL_PASS' }
        } else { Write-Host 'RELATIVE_ATTRIBUTE_REPARSE_UNSUPPORTED_NOT_TESTED' }
    }
} catch {
    # Avoid emitting raw exception paths, ACLs, IDs, or OS diagnostic details.
    $category = $_.Exception.Message
    if ($category -cmatch '^RELATIVE_[A-Z_]+$') { throw $category }
    throw 'RELATIVE_DIRECTORY_FIXTURE_FAILED'
} finally {
    if ($cleanupSafe) { Remove-Item -LiteralPath $root -Recurse -Force }
}
