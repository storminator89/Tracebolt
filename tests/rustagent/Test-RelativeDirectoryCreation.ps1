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
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
        static extern bool MoveFileExW(string source, string target, uint flags);
        public static int TryRenameOwnedFixture(string source, string target) {
            // Same-volume ordinary rename only. Never delayed reboot or copy fallback.
            return MoveFileExW(source, target, 1) ? 0 : Marshal.GetLastWin32Error();
        }
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
$failureStage = 'setup'
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

    $failureStage = 'health-rename-sharing'
    # Synthetic bytes in new random TEMP objects only, never the installed agent's
    # actual health files. Isolate destination-parent sharing without ACL changes.
    $p = New-RelativeParent; $stateParent = Join-Path $p 'state'
    [IO.Directory]::CreateDirectory($stateParent) | Out-Null
    $inertBytes = [byte[]]@(83,72,65,82,69)
    $sourceLeaf = Join-Path $stateParent 'health-v1.tmp'; $targetLeaf = Join-Path $stateParent 'health-v1.json'
    $file = [IO.File]::Open($sourceLeaf, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $file.Write($inertBytes,0,$inertBytes.Length); $file.Flush($true) } finally { $file.Dispose() }
    $lease = [Tracebolt.InstallDirectoryLease]::Acquire([string[]]@($stateParent))
    try {
        $renameError = [Tracebolt.RelativeDirectoryFixture]::TryRenameOwnedFixture($sourceLeaf,$targetLeaf)
        Write-Host ('RELATIVE_HEALTH_STRICT_STATE_RENAME_CODE={0}' -f $renameError)
        Assert-Relative ($renameError -eq 32) 'RELATIVE_HEALTH_RENAME_NOT_SHARING_VIOLATION'
        Assert-Relative ([IO.File]::Exists($sourceLeaf) -and ![IO.File]::Exists($targetLeaf)) 'RELATIVE_HEALTH_BLOCKED_RENAME_CHANGED_NAMES'
        Assert-Relative ([Convert]::ToBase64String([IO.File]::ReadAllBytes($sourceLeaf)) -ceq [Convert]::ToBase64String($inertBytes)) 'RELATIVE_HEALTH_BLOCKED_RENAME_CHANGED_BYTES'
    } finally { $lease.Dispose() }
    Assert-Relative ([Tracebolt.RelativeDirectoryFixture]::TryRenameOwnedFixture($sourceLeaf,$targetLeaf) -eq 0) 'RELATIVE_HEALTH_RELEASED_RENAME_FAILED'
    Assert-Relative (![IO.File]::Exists($sourceLeaf) -and [IO.File]::Exists($targetLeaf)) 'RELATIVE_HEALTH_RELEASED_RENAME_MISSING'
    Assert-Relative ([Convert]::ToBase64String([IO.File]::ReadAllBytes($targetLeaf)) -ceq [Convert]::ToBase64String($inertBytes)) 'RELATIVE_HEALTH_RELEASED_RENAME_CHANGED_BYTES'
    Write-Host 'RELATIVE_HEALTH_STRICT_STATE_LEASE_BLOCKED_32_AND_RELEASED_RENAME_PASS'

    $p = New-RelativeParent; $stateParent = Join-Path $p 'state'
    [IO.Directory]::CreateDirectory($stateParent) | Out-Null
    $sourceLeaf = Join-Path $stateParent 'health-v1.tmp'; $targetLeaf = Join-Path $stateParent 'health-v1.json'
    $file = [IO.File]::Open($sourceLeaf, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $file.Write($inertBytes,0,$inertBytes.Length); $file.Flush($true) } finally { $file.Dispose() }
    $lease = [Tracebolt.InstallDirectoryLease]::Acquire([string[]]@($p))
    $permissiveState = $null
    try {
        # Control: all ancestors including the data parent remain strict. This
        # fixture-only ordinary state handle shares read/write/delete; production
        # lease behavior is unchanged and no handoff is implemented here.
        $permissiveState = [Tracebolt.RelativeDirectoryFixture]::Open($stateParent,[uint32]2147483648)
        Assert-Relative ($null -ne $permissiveState) 'RELATIVE_HEALTH_CONTROL_STATE_OPEN_FAILED'
        Assert-Relative ([Tracebolt.RelativeDirectoryFixture]::TryRenameOwnedFixture($sourceLeaf,$targetLeaf) -eq 0) 'RELATIVE_HEALTH_PINNED_PARENT_CONTROL_RENAME_FAILED'
        Assert-Relative (![IO.File]::Exists($sourceLeaf) -and [IO.File]::Exists($targetLeaf)) 'RELATIVE_HEALTH_PINNED_PARENT_CONTROL_MISSING'
        Assert-Relative ([Convert]::ToBase64String([IO.File]::ReadAllBytes($targetLeaf)) -ceq [Convert]::ToBase64String($inertBytes)) 'RELATIVE_HEALTH_PINNED_PARENT_CONTROL_CHANGED_BYTES'
    } finally {
        if ($null -ne $permissiveState) { $permissiveState.Dispose() }
        $lease.Dispose()
    }
    Write-Host 'RELATIVE_HEALTH_PINNED_DATA_PARENT_PERMISSIVE_STATE_CONTROL_PASS'

    $failureStage = 'lease-acquire'
    $p = New-RelativeParent; $unrelated = New-RelativeParent
    $child = Join-Path $p 'state'; $otherChild = Join-Path $unrelated 'state'
    $lease = [Tracebolt.InstallDirectoryLease]::Acquire([string[]]@($p))
    try {
        # Namespace-only unit proof under our user-owned TEMP ancestry. The
        # production public method additionally requires real owner/DACL review;
        # a TEMP fixture is not relabeled as a production-trusted ancestor.
        $failureStage = 'lease-core-lookup'
        $namespaceCore = [Tracebolt.InstallDirectoryLease].GetMethod('CreateProtectedChildCore', [Reflection.BindingFlags]::Instance -bor [Reflection.BindingFlags]::NonPublic)
        Assert-Relative ($null -ne $namespaceCore) 'RELATIVE_LEASE_CORE_UNAVAILABLE'
        $failureStage = 'lease-core-invoke'
        # Join-Path returns a PSObject-wrapped string; reflection's object[]
        # binder does not unwrap it as an ordinary PowerShell method call does.
        [void]$namespaceCore.Invoke($lease, [object[]]@([string]$child))
        $failureStage = 'lease-bound-assert'
        Assert-Relative ($lease.Covers($child) -and $lease.HasBoundChild($p)) 'RELATIVE_LEASE_CHILD_NOT_BOUND'
        $failureStage = 'lease-require-bound'
        $lease.RequireBoundChild($child)
        $failureStage = 'lease-rename'
        $renamed = $false
        try { [IO.Directory]::Move($child, (Join-Path $p 'renamed')); $renamed = $true } catch { }
        Assert-Relative (!$renamed -and [IO.Directory]::Exists($child)) 'RELATIVE_LEASE_RENAME_NOT_BLOCKED'
        $failureStage = 'lease-unrelated-parent'
        $accepted = $false
        try { $lease.CreateProtectedChild($otherChild); $accepted = $true } catch { }
        Assert-Relative (!$accepted -and ![IO.Directory]::Exists($otherChild)) 'RELATIVE_UNRELATED_PARENT_ACCEPTED'
        Assert-Relative (@([IO.Directory]::EnumerateFileSystemEntries($unrelated)).Count -eq 0) 'RELATIVE_UNRELATED_PARENT_CHANGED'
    } finally { $lease.Dispose() }
    $failureStage = 'lease-disposal'
    Assert-Relative (!$lease.Covers($p) -and !$lease.Covers($child) -and !$lease.HasBoundChild($p)) 'RELATIVE_DISPOSED_LEASE_COVERS'
    $disposedChild = Join-Path $p 'TraceboltRust'; $accepted = $false
    try { $lease.CreateProtectedChild($disposedChild); $accepted = $true } catch { }
    Assert-Relative (!$accepted -and ![IO.Directory]::Exists($disposedChild)) 'RELATIVE_DISPOSED_LEASE_ACCEPTED'
    $p = New-RelativeParent
    $h = [Tracebolt.RustInstallerPath]::Open($p, $true); $h.Dispose()
    Assert-Relative (!(Invoke-RelativeAttempt $h)) 'RELATIVE_DISPOSED_PARENT_ACCEPTED'
    Assert-Relative (@([IO.Directory]::EnumerateFileSystemEntries($p)).Count -eq 0) 'RELATIVE_DISPOSED_PARENT_CHANGED'
    Write-Host 'RELATIVE_LEASE_BINDING_RENAME_AND_DISPOSAL_PASS'
    $failureStage = 'post-lease-fixtures'

    $p = New-RelativeParent; $collision = Join-Path $p 'state'
    [IO.File]::WriteAllText($collision, 'preserve collision; no bound-child authority')
    $lease = [Tracebolt.InstallDirectoryLease]::Acquire([string[]]@($p))
    try {
        $failed = $false
        try { [void]$namespaceCore.Invoke($lease, [object[]]@([string]$collision)) } catch { $failed = $true }
        Assert-Relative ($failed -and !$lease.HasBoundChild($p)) 'RELATIVE_FAILED_CREATE_GAINED_PROOF'
        $failed = $false
        try { $lease.RequireBoundChild($collision) } catch { $failed = $true }
        Assert-Relative $failed 'RELATIVE_FAILED_CREATE_PATH_GATE_ACCEPTED'
        Assert-Relative ([IO.File]::ReadAllText($collision) -ceq 'preserve collision; no bound-child authority') 'RELATIVE_FAILED_CREATE_CHANGED_COLLISION'
    } finally { $lease.Dispose() }
    Write-Host 'RELATIVE_FAILED_CREATE_HAS_NO_BOUND_AUTHORITY_PASS'

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
    # State-only handoff bookkeeping in owned TEMP. Private namespace/release
    # cores deliberately isolate mechanics from production KnownFolder/ACL gates.
    $failureStage = 'state-handoff-fixture'
    $p = New-RelativeParent; $stateParent = Join-Path $p 'state'
    $releaseCore = [Tracebolt.InstallDirectoryLease].GetMethod('ReleaseBoundStateCore',
        [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Instance,
        $null, [type[]]@([string], [string]), $null)
    Assert-Relative ($null -ne $releaseCore) 'RELATIVE_HANDOFF_CORE_MISSING'
    $lease = [Tracebolt.InstallDirectoryLease]::Acquire([string[]]@($p))
    try {
        [void]$namespaceCore.Invoke($lease, [object[]]@([string]$stateParent))
        $subtree = Join-Path $stateParent 'owned-child'
        [IO.Directory]::CreateDirectory($subtree) | Out-Null
        $sourceLeaf = Join-Path $stateParent 'health-v1.tmp'; $targetLeaf = Join-Path $stateParent 'health-v1.json'
        [IO.File]::WriteAllBytes($sourceLeaf, $inertBytes)
        $rejected = $false
        try { $lease.HandoffRuntimeStateForServiceStart() } catch { $rejected = $true }
        Assert-Relative ($rejected -and $lease.Covers($p) -and $lease.Covers($stateParent) -and $lease.HasBoundChild($p)) 'RELATIVE_UNRELATED_HANDOFF_DROPPED_PROOF'
        foreach ($badPair in @(@($p, (Join-Path $p 'TraceboltRust')), @($root, $stateParent), @($p, $subtree))) {
            $rejected = $false
            try { [void]$releaseCore.Invoke($lease, [object[]]@([string]$badPair[0], [string]$badPair[1])) } catch { $rejected = $true }
            Assert-Relative ($rejected -and $lease.Covers($stateParent) -and $lease.HasBoundChild($p)) 'RELATIVE_HANDOFF_INVALID_CORE_DROPPED_PROOF'
        }
        Assert-Relative ([Tracebolt.RelativeDirectoryFixture]::TryRenameOwnedFixture($sourceLeaf,$targetLeaf) -eq 32) 'RELATIVE_HANDOFF_PRECONDITION_RENAME_NOT_BLOCKED'
        [void]$releaseCore.Invoke($lease, [object[]]@([string]$p, [string]$stateParent))
        Assert-Relative ($lease.Covers($p) -and !$lease.Covers($stateParent) -and !$lease.HasBoundChild($p)) 'RELATIVE_HANDOFF_STATE_ONLY_RELEASE_FAILED'
        $rejected = $false
        try { $lease.RequireBoundChild($stateParent) } catch { $rejected = $true }
        Assert-Relative $rejected 'RELATIVE_HANDOFF_RETAINED_STATE_AUTHORITY'
        $renamed = $false
        try { [IO.Directory]::Move($p, ($p + '-renamed')); $renamed = $true } catch { }
        Assert-Relative (!$renamed -and [IO.Directory]::Exists($p)) 'RELATIVE_HANDOFF_PARENT_NOT_PINNED'
        Assert-Relative ([Tracebolt.RelativeDirectoryFixture]::TryRenameOwnedFixture($sourceLeaf,$targetLeaf) -eq 0) 'RELATIVE_HANDOFF_HEALTH_RENAME_FAILED'
        Assert-Relative (![IO.File]::Exists($sourceLeaf) -and [IO.File]::Exists($targetLeaf)) 'RELATIVE_HANDOFF_HEALTH_NAMES_CHANGED'
        Assert-Relative ([Convert]::ToBase64String([IO.File]::ReadAllBytes($targetLeaf)) -ceq [Convert]::ToBase64String($inertBytes)) 'RELATIVE_HANDOFF_HEALTH_BYTES_CHANGED'
        foreach ($repin in @($stateParent, (Join-Path $p 'STATE'), $subtree)) {
            $rejected = $false
            try { $lease.Pin($repin) } catch { $rejected = $true }
            Assert-Relative ($rejected -and !$lease.Covers($stateParent)) 'RELATIVE_HANDOFF_STATE_REPIN_ACCEPTED'
        }
        $rejected = $false
        try { [void]$releaseCore.Invoke($lease, [object[]]@([string]$p, [string]$stateParent)) } catch { $rejected = $true }
        Assert-Relative $rejected 'RELATIVE_HANDOFF_REPEAT_RELEASE_ACCEPTED'
    } finally { $lease.Dispose() }
    $rejected = $false
    try { $lease.HandoffRuntimeStateForServiceStart() } catch { $rejected = $true }
    Assert-Relative $rejected 'RELATIVE_DISPOSED_HANDOFF_ACCEPTED'
    $rejected = $false
    try { [void]$releaseCore.Invoke($lease, [object[]]@([string]$p, [string]$stateParent)) } catch { $rejected = $true }
    Assert-Relative $rejected 'RELATIVE_DISPOSED_HANDOFF_CORE_ACCEPTED'
    Write-Host 'RELATIVE_STATE_ONLY_HANDOFF_PARENT_PINNED_RENAME_AND_NO_REPIN_PASS'
    $unboundParent = New-RelativeParent; $unboundState = Join-Path $unboundParent 'state'
    [IO.Directory]::CreateDirectory($unboundState) | Out-Null
    $unboundLease = [Tracebolt.InstallDirectoryLease]::Acquire([string[]]@($unboundParent))
    try {
        $rejected = $false
        try { [void]$releaseCore.Invoke($unboundLease, [object[]]@([string]$unboundParent, [string]$unboundState)) } catch { $rejected = $true }
        Assert-Relative ($rejected -and $unboundLease.Covers($unboundParent) -and !$unboundLease.Covers($unboundState) -and !$unboundLease.HasBoundChild($unboundParent)) 'RELATIVE_UNBOUND_EXACT_STATE_HANDOFF_ACCEPTED'
        Assert-Relative ([IO.Directory]::Exists($unboundState) -and @([IO.Directory]::EnumerateFileSystemEntries($unboundState)).Count -eq 0) 'RELATIVE_UNBOUND_EXACT_STATE_CHANGED'
    } finally { $unboundLease.Dispose() }
    Write-Host 'RELATIVE_UNBOUND_EXACT_STATE_HANDOFF_REJECTED_PASS'


    # Pure descriptor fixtures: no Set-Acl, real service lookup or ACL writes.
    $failureStage = 'state-handoff-descriptor-fixture'
    $protectionCore = [Tracebolt.InstallDirectoryLease].GetMethod('RequireServiceDirectoryProtection',
        [Reflection.BindingFlags]::NonPublic -bor [Reflection.BindingFlags]::Static,
        $null, [type[]]@([byte[]], [string], [uint32]), $null)
    Assert-Relative ($null -ne $protectionCore) 'RELATIVE_SERVICE_PROTECTION_CORE_MISSING'
    $fixtureServiceSid = 'S-1-5-80-1-2-3-4-5'
    function Assert-ServiceProtectionFixture($Descriptor, [uint32]$Mask, [bool]$Expected) {
        $bytes = New-Object byte[] $Descriptor.BinaryLength
        $Descriptor.GetBinaryForm($bytes, 0)
        $accepted = $true
        try { [void]$protectionCore.Invoke($null, [object[]]@([byte[]]$bytes, [string]$fixtureServiceSid, [uint32]$Mask)) }
        catch { $accepted = $false }
        Assert-Relative ($accepted -eq $Expected) 'RELATIVE_SERVICE_PROTECTION_CLASSIFICATION_MISMATCH'
    }
    foreach ($mask in @([uint32]0x1200a9, [uint32]0x1301bf)) {
        $maskText = '0x{0:x}' -f $mask
        $baseAces = '(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)'
        $serviceAce = "(A;OICI;$maskText;;;$fixtureServiceSid)"
        $validSddl = 'O:BAG:BAD:P' + $baseAces + $serviceAce
        Assert-ServiceProtectionFixture ([Security.AccessControl.RawSecurityDescriptor]::new($validSddl)) $mask $true
        $negativeSddl = @(
            ('O:SYG:BAD:P' + $baseAces + $serviceAce),
            'O:BAG:BAD:NO_ACCESS_CONTROL',
            ('O:BAG:BAD:' + $baseAces + $serviceAce),
            ('O:BAG:BAD:P' + $baseAces),
            ($validSddl + '(A;OICI;FR;;;BU)'),
            ('O:BAG:BAD:P' + $baseAces + "(A;OICI;$maskText;;;S-1-5-80-5-4-3-2-1)"),
            ('O:BAG:BAD:P' + $baseAces + "(A;OICI;FA;;;$fixtureServiceSid)"),
            ('O:BAG:BAD:P' + $baseAces + "(A;CI;$maskText;;;$fixtureServiceSid)"),
            ('O:BAG:BAD:P' + $baseAces + "(A;OICIIO;$maskText;;;$fixtureServiceSid)"),
            ('O:BAG:BAD:P' + $baseAces + "(D;OICI;$maskText;;;$fixtureServiceSid)"),
            ('O:BAG:BAD:P' + $baseAces + '(A;OICI;FA;;;BA)')
        )
        foreach ($sddl in $negativeSddl) {
            Assert-ServiceProtectionFixture ([Security.AccessControl.RawSecurityDescriptor]::new($sddl)) $mask $false
        }
        foreach ($form in @('callback', 'object')) {
            $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($validSddl)
            $sid = [Security.Principal.SecurityIdentifier]::new($fixtureServiceSid)
            $flags = [Security.AccessControl.AceFlags]::ObjectInherit -bor [Security.AccessControl.AceFlags]::ContainerInherit
            if ($form -eq 'callback') {
                $ace = [Security.AccessControl.CommonAce]::new($flags,
                    [Security.AccessControl.AceQualifier]::AccessAllowed, [int]$mask, $sid, $true, [byte[]]@())
            } else {
                $ace = [Security.AccessControl.ObjectAce]::new($flags,
                    [Security.AccessControl.AceQualifier]::AccessAllowed, [int]$mask, $sid,
                    [Security.AccessControl.ObjectAceFlags]::None, [Guid]::Empty, [Guid]::Empty, $false, [byte[]]@())
            }
            $acl = [Security.AccessControl.RawAcl]::new(4, 3)
            $acl.InsertAce(0, $descriptor.DiscretionaryAcl[0]); $acl.InsertAce(1, $descriptor.DiscretionaryAcl[1]); $acl.InsertAce(2, $ace)
            $descriptor.DiscretionaryAcl = $acl
            Assert-ServiceProtectionFixture $descriptor $mask $false
        }
    }
    Write-Host 'RELATIVE_SERVICE_HANDOFF_DESCRIPTOR_ONLY_POLICY_PASS'
} catch {
    # Avoid emitting raw exception paths, ACLs, IDs, or OS diagnostic details.
    $cause = $_.Exception.GetBaseException()
    $category = $cause.Message
    if ($category -cmatch '^RELATIVE_[A-Z_]+$') { throw $category }
    # Only a source-fixed stage and bounded numeric error codes, never raw text.
    $nativeCode = if ($cause -is [ComponentModel.Win32Exception]) { [int]$cause.NativeErrorCode } else { 0 }
    Write-Host ('RELATIVE_FAILURE stage={0} hresult={1} native={2}' -f $failureStage, [int]$cause.HResult, $nativeCode)
    throw 'RELATIVE_DIRECTORY_FIXTURE_FAILED'
} finally {
    if ($cleanupSafe) { Remove-Item -LiteralPath $root -Recurse -Force }
}
