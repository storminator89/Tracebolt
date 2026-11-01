# Read-only package checks. Hashes establish consistency, not publisher trust.
# Dot-source only from the independently reviewed installer/package.
function Initialize-TraceboltInstallerType {
    if (!('Tracebolt.RustInstallerPath' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Text;
using Microsoft.Win32.SafeHandles;
namespace Tracebolt {
    public static class RustInstallerPath {
        [StructLayout(LayoutKind.Sequential)]
        private struct FileInformation {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct UnicodeName { public ushort Length, MaximumLength; public IntPtr Buffer; }
        [StructLayout(LayoutKind.Sequential)]
        private struct ObjectAttributes {
            public uint Length; public IntPtr RootDirectory, ObjectName;
            public uint Attributes; public IntPtr SecurityDescriptor, SecurityQualityOfService;
        }
        [StructLayout(LayoutKind.Sequential)]
        private struct IoStatusBlock { public IntPtr Status; public UIntPtr Information; }
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint size);
        [DllImport("advapi32.dll", ExactSpelling=true)]
        private static extern uint GetSecurityInfo(SafeFileHandle handle, uint type, uint information, out IntPtr owner, out IntPtr group,
            out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
        [DllImport("advapi32.dll", ExactSpelling=true)]
        private static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
        private static extern uint GetFinalPathNameByHandleW(SafeFileHandle handle, StringBuilder path, uint size, uint flags);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
        private static extern bool GetVolumeInformationByHandleW(SafeFileHandle handle, StringBuilder volumeName, uint volumeNameSize,
            out uint serial, out uint maximumComponentLength, out uint flags, StringBuilder fileSystemName, uint fileSystemNameSize);
        [DllImport("ntdll.dll", ExactSpelling=true)]
        private static extern int NtCreateFile(out IntPtr handle, uint access, ref ObjectAttributes attributes, out IoStatusBlock status,
            IntPtr allocationSize, uint fileAttributes, uint shareAccess, uint disposition, uint options, IntPtr eaBuffer, uint eaLength);
        [DllImport("ntdll.dll", ExactSpelling=true)]
        private static extern uint RtlNtStatusToDosError(int status);
        [DllImport("kernel32.dll", ExactSpelling=true)]
        private static extern IntPtr LocalFree(IntPtr memory);
        private static FileInformation DirectoryInformation(SafeFileHandle handle) {
            FileInformation information;
            if (handle.IsInvalid || handle.IsClosed || !GetFileInformationByHandle(handle, out information))
                throw new IOException("Directory identity is unavailable.");
            if ((information.Attributes & 0x400) != 0 || (information.Attributes & 0x10) == 0)
                throw new IOException("Directory is not an ordinary no-follow object.");
            return information;
        }
        public static string FinalDirectoryPath(SafeFileHandle handle) {
            DirectoryInformation(handle);
            var buffer = new StringBuilder(4096);
            uint length = GetFinalPathNameByHandleW(handle, buffer, 4096, 1); // normalized, volume-GUID qualified
            if (length == 0 || length >= 4096) throw new IOException("Directory final-path identity is unavailable.");
            return buffer.ToString().TrimEnd('\\');
        }
        public static bool SameDirectoryObject(SafeFileHandle left, SafeFileHandle right) {
            var a = DirectoryInformation(left); var b = DirectoryInformation(right);
            return a.Volume == b.Volume && a.IndexHigh == b.IndexHigh && a.IndexLow == b.IndexLow;
        }
        private static void RequireNtfs(SafeFileHandle parent) {
            var name = new StringBuilder(32);
            uint serial, maximumComponentLength, flags;
            if (!GetVolumeInformationByHandleW(parent, null, 0, out serial, out maximumComponentLength, out flags, name, 32) ||
                !string.Equals(name.ToString(), "NTFS", StringComparison.Ordinal))
                throw new IOException("Relative protected creation requires the reviewed local NTFS contract.");
        }
        private static void RequireFreshProtection(SafeFileHandle child) {
            IntPtr owner, group, dacl, sacl, descriptor;
            uint result = GetSecurityInfo(child, 1, 5, out owner, out group, out dacl, out sacl, out descriptor);
            if (result != 0 || descriptor == IntPtr.Zero) throw new IOException("Fresh directory protection is unavailable.");
            try {
                uint length = GetSecurityDescriptorLength(descriptor);
                if (length == 0 || length > 65536) throw new IOException("Fresh directory descriptor is unsupported.");
                var bytes = new byte[(int)length];
                Marshal.Copy(descriptor, bytes, 0, bytes.Length);
                var security = new RawSecurityDescriptor(bytes, 0);
                if (security.Owner == null || security.Owner.Value != "S-1-5-32-544" || security.DiscretionaryAcl == null ||
                    (security.ControlFlags & (ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected)) !=
                        (ControlFlags.DiscretionaryAclPresent | ControlFlags.DiscretionaryAclProtected) || security.DiscretionaryAcl.Count != 2)
                    throw new IOException("Fresh directory owner or protected ACL mismatch.");
                var seen = new HashSet<string>(StringComparer.Ordinal);
                foreach (GenericAce entry in security.DiscretionaryAcl) {
                    var ace = entry as CommonAce;
                    if (ace == null || ace.IsCallback || ace.AceQualifier != AceQualifier.AccessAllowed || ace.AccessMask != 0x001f01ff ||
                        ace.AceFlags != (AceFlags.ContainerInherit | AceFlags.ObjectInherit) ||
                        (ace.SecurityIdentifier.Value != "S-1-5-18" && ace.SecurityIdentifier.Value != "S-1-5-32-544") ||
                        !seen.Add(ace.SecurityIdentifier.Value))
                        throw new IOException("Fresh directory ACL is not the exact protected creation policy.");
                }
            } finally { if (descriptor != IntPtr.Zero) LocalFree(descriptor); }
        }
        public static SafeFileHandle CreateRelativeDirectory(SafeFileHandle parent, string leaf) {
            return CreateRelativeDirectoryCore(parent, leaf, null);
        }
        // No public callback route. The owned TEMP fixture reflects this private
        // core only to place a reparse change at the last pre-NtCreateFile edge.
        private static SafeFileHandle CreateRelativeDirectoryCore(SafeFileHandle parent, string leaf, Action beforeNative) {
            // No paths, ADS, dot components, arbitrary installer input or fallback.
            if (leaf != "state" && leaf != "TraceboltRust" && leaf != "Tracebolt Rust")
                throw new IOException("Only a fixed installation child component is supported.");
            bool parentReference = false;
            IntPtr descriptor = IntPtr.Zero, nameBuffer = IntPtr.Zero, namePointer = IntPtr.Zero;
            SafeFileHandle child = null;
            try {
                parent.DangerousAddRef(ref parentReference);
                var before = DirectoryInformation(parent);
                RequireNtfs(parent);
                string parentPath = FinalDirectoryPath(parent);
                uint descriptorSize;
                if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", 1, out descriptor, out descriptorSize))
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                nameBuffer = Marshal.StringToHGlobalUni(leaf);
                var name = new UnicodeName { Length=(ushort)(leaf.Length * 2), MaximumLength=(ushort)(leaf.Length * 2 + 2), Buffer=nameBuffer };
                namePointer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UnicodeName)));
                Marshal.StructureToPtr(name, namePointer, false);
                var attributes = new ObjectAttributes {
                    Length=(uint)Marshal.SizeOf(typeof(ObjectAttributes)), RootDirectory=parent.DangerousGetHandle(),
                    ObjectName=namePointer, Attributes=0x1000, SecurityDescriptor=descriptor, SecurityQualityOfService=IntPtr.Zero
                }; // OBJ_DONT_REPARSE; never OBJ_OPENIF or inherited handles.
                IoStatusBlock status;
                IntPtr rawChild;
                if (beforeNative != null) beforeNative(); // deterministic isolated fixture checkpoint only
                int result = NtCreateFile(out rawChild, 0x00120089, ref attributes, out status, IntPtr.Zero,
                    0x10, 1, 2, 0x00200021, IntPtr.Zero, 0);
                // FILE_GENERIC_READ; share-read only; FILE_CREATE;
                // DIRECTORY_FILE | SYNCHRONOUS_IO_NONALERT | OPEN_REPARSE_POINT.
                if (rawChild != IntPtr.Zero && rawChild != new IntPtr(-1)) child = new SafeFileHandle(rawChild, true);
                if (result != 0) throw new Win32Exception((int)RtlNtStatusToDosError(result));
                if (child == null || status.Information.ToUInt64() != 2)
                    throw new IOException("Fresh directory creation was not confirmed."); // FILE_CREATED, never adoption.
                DirectoryInformation(child);
                RequireFreshProtection(child);
                var after = DirectoryInformation(parent);
                if (before.Volume != after.Volume || before.IndexHigh != after.IndexHigh || before.IndexLow != after.IndexLow ||
                    !string.Equals(parentPath, FinalDirectoryPath(parent), StringComparison.Ordinal) ||
                    !string.Equals(parentPath + "\\" + leaf, FinalDirectoryPath(child), StringComparison.Ordinal))
                    throw new IOException("Relative directory identity or containment is uncertain; staging retained.");
                // The returned handle is retained without any reopen gap.
                return child;
            } catch { if (child != null) child.Dispose(); throw; }
            finally {
                if (namePointer != IntPtr.Zero) Marshal.FreeHGlobal(namePointer);
                if (nameBuffer != IntPtr.Zero) Marshal.FreeHGlobal(nameBuffer);
                if (descriptor != IntPtr.Zero) LocalFree(descriptor);
                if (parentReference) parent.DangerousRelease();
            }
        }
        public static bool IsOrdinaryDirectory(SafeFileHandle handle) {
            FileInformation information;
            return !handle.IsInvalid && !handle.IsClosed && GetFileInformationByHandle(handle, out information) &&
                (information.Attributes & 0x400) == 0 && (information.Attributes & 0x10) != 0;
        }
        public static SafeFileHandle Open(string path, bool directory) {
            // OPEN_REPARSE_POINT inspects the selected object, not a link target.
            // Share-read denies data-write/delete handles, not attribute/EA access.
            // Actual read access is required for share accounting; an access=0
            // metadata-only directory open is not a namespace lock.
            var handle = CreateFileW(path, 0x80000000u, 1, IntPtr.Zero, 3, 0x00200000u | (directory ? 0x02000000u : 0u), IntPtr.Zero);
            if (handle.IsInvalid) { int error=Marshal.GetLastWin32Error(); handle.Dispose(); throw new Win32Exception(error); }
            try {
                FileInformation information;
                if (!GetFileInformationByHandle(handle, out information)) throw new Win32Exception(Marshal.GetLastWin32Error());
                if ((information.Attributes & 0x400) != 0 || ((information.Attributes & 0x10) != 0) != directory)
                    throw new IOException("Links or unexpected path types are unsupported.");
                return handle;
            } catch { handle.Dispose(); throw; }
        }
    }
    // Own actual handles, not a caller-supplied "checked" flag or path roster.
    public sealed class InstallDirectoryLease : IDisposable {
        private readonly object gate = new object();
        private readonly Dictionary<string, SafeFileHandle> handles = new Dictionary<string, SafeFileHandle>(StringComparer.Ordinal);
        private readonly Dictionary<string, string> createdChildren = new Dictionary<string, string>(StringComparer.Ordinal);
        private bool disposed;
        private InstallDirectoryLease() { }
        private static string Canonical(string path) {
            string full = Path.GetFullPath(path);
            if (full.Length < 3 || !char.IsLetter(full[0]) || full[1] != ':' || full[2] != '\\' || full.IndexOf(':', 2) >= 0)
                throw new IOException("Only local drive directories are supported.");
            string root = Path.GetPathRoot(full);
            return full.Length == root.Length ? full : full.TrimEnd('\\', '/');
        }
        public static InstallDirectoryLease Acquire(string[] paths) {
            var lease = new InstallDirectoryLease();
            try { foreach (string path in paths) lease.Pin(path); return lease; }
            catch { lease.Dispose(); throw; }
        }
        public void Pin(string path) {
            lock (gate) {
            if (disposed) throw new ObjectDisposedException("InstallDirectoryLease");
            var chain = new List<string>();
            var current = new DirectoryInfo(Canonical(path));
            while (current != null) { chain.Insert(0, Canonical(current.FullName)); current = current.Parent; }
            foreach (string ancestor in chain) {
                SafeFileHandle handle;
                if (handles.TryGetValue(ancestor, out handle)) {
                    if (!RustInstallerPath.IsOrdinaryDirectory(handle)) throw new IOException("Directory lease is unavailable.");
                } else {
                    handle = RustInstallerPath.Open(ancestor, true);
                    handles.Add(ancestor, handle);
                }
            }
            }
        }
        public bool Covers(string path) {
            lock (gate) {
            if (disposed) return false;
            SafeFileHandle handle;
            return handles.TryGetValue(Canonical(path), out handle) && RustInstallerPath.IsOrdinaryDirectory(handle);
            }
        }
        public void CreateProtectedChild(string path) {
            lock (gate) {
                if (disposed) throw new ObjectDisposedException("InstallDirectoryLease");
                string full = Canonical(path);
                var parentDirectory = new DirectoryInfo(full).Parent;
                if (parentDirectory == null) throw new IOException("A fixed child needs a leased parent.");
                string parent = Canonical(parentDirectory.FullName);
                if (!Covers(parent) || handles.ContainsKey(full)) throw new IOException("Exact fresh child admission is unavailable.");
                SafeFileHandle child = RustInstallerPath.CreateRelativeDirectory(handles[parent], Path.GetFileName(full));
                try {
                    // This path lookup is verification only, never creation.
                    // Before any copy/init/SCM operation it must name the exact
                    // object returned by the handle-relative exclusive create.
                    using (var actual = RustInstallerPath.Open(full, true)) {
                        if (!RustInstallerPath.SameDirectoryObject(child, actual) ||
                            !string.Equals(RustInstallerPath.FinalDirectoryPath(child), RustInstallerPath.FinalDirectoryPath(actual), StringComparison.Ordinal))
                            throw new IOException("Created child does not match the intended full-path object; staging retained.");
                    }
                    if (!Covers(parent)) throw new IOException("Parent changed during protected creation; staging retained.");
                    handles.Add(full, child);
                    createdChildren[parent] = full;
                    child = null;
                } finally { if (child != null) child.Dispose(); }
            }
        }
        public bool HasBoundChild(string parentPath) {
            lock (gate) {
                if (disposed) return false;
                string parent = Canonical(parentPath), child;
                return createdChildren.TryGetValue(parent, out child) && Covers(parent) && Covers(child) &&
                    string.Equals(RustInstallerPath.FinalDirectoryPath(handles[parent]) + "\\" + Path.GetFileName(child),
                        RustInstallerPath.FinalDirectoryPath(handles[child]), StringComparison.Ordinal);
            }
        }
        public void Dispose() {
            lock (gate) {
            if (disposed) return;
            disposed = true;
            foreach (SafeFileHandle handle in handles.Values) handle.Dispose();
            }
        }
    }
}
'@
    }
}

function Open-TraceboltReadFile([string]$Path) {
    if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
        Initialize-TraceboltInstallerType
        $handle = [Tracebolt.RustInstallerPath]::Open($Path, $false)
        try { return [IO.FileStream]::new($handle, [IO.FileAccess]::Read) } catch { $handle.Dispose(); throw }
    }
    # Portable data-fixture support only; Windows sharing/namespace acceptance is separate.
    return [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
}

function Assert-TraceboltPlainPath([string]$Path, [switch]$Directory) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.StartsWith('\\') -or $full.Substring(2).Contains(':')) {
        throw 'Only local filesystem paths without alternate streams are supported.'
    }
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    if ($item.PSIsContainer -ne [bool]$Directory) { throw 'Unexpected package or installation path type.' }
    $current = $item
    while ($null -ne $current) {
        if ($current.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Reparse points are not supported in package, input or installation paths.'
        }
        if ($current -is [IO.FileInfo]) { $current = $current.Directory } else { $current = $current.Parent }
    }
    return $full
}

function Get-TraceboltStreamHash([IO.Stream]$Stream) {
    $hash = [Security.Cryptography.SHA256]::Create()
    try {
        $Stream.Position = 0
        return ([BitConverter]::ToString($hash.ComputeHash($Stream))).Replace('-', '').ToLowerInvariant()
    } finally { $Stream.Position = 0; $hash.Dispose() }
}

function Assert-TraceboltAmd64Image([IO.Stream]$Stream) {
    # Inspect only as data, before the first invocation of an arbitrary EXE.
    $reader = [IO.BinaryReader]::new($Stream, [Text.Encoding]::ASCII, $true)
    try {
        if ($Stream.Length -lt 64 -or $Stream.Length -gt 134217728) { throw 'Invalid executable size.' }
        $Stream.Position = 0
        if ($reader.ReadUInt16() -ne 0x5a4d) { throw 'Executable is not a PE image.' }
        $Stream.Position = 0x3c
        $offset = $reader.ReadUInt32()
        if ($offset -lt 64 -or $offset -gt ($Stream.Length - 136)) { throw 'Invalid PE header bounds.' }
        $Stream.Position = $offset
        if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne 0x8664) {
            throw 'Executable must be a Windows AMD64 PE image.'
        }
        $Stream.Position = $offset + 20
        $optionalBytes = $reader.ReadUInt16()
        $characteristics = $reader.ReadUInt16()
        if ($optionalBytes -lt 112 -or ($offset + 24 + $optionalBytes) -gt $Stream.Length -or
            !($characteristics -band 2) -or ($characteristics -band 0x2000) -or $reader.ReadUInt16() -ne 0x20b) {
            throw 'Executable must be an AMD64 executable, not a DLL or malformed image.'
        }
    } finally { $reader.Dispose(); $Stream.Position = 0 }
}

function Open-TraceboltPackage([string]$Executable, [string]$PackageDirectory) {
    $streams = New-Object 'System.Collections.Generic.List[System.IDisposable]'
    try {
        $root = Assert-TraceboltPlainPath $PackageDirectory -Directory
        if ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT) {
            if ($root -notmatch '^[A-Za-z]:\\') { throw 'Package must be on a local Windows drive.' }
            Initialize-TraceboltInstallerType
            $ancestors = New-Object 'System.Collections.Generic.List[string]'
            $current = [IO.DirectoryInfo]::new($root)
            while ($null -ne $current) { $ancestors.Insert(0, $current.FullName); $current = $current.Parent }
            # Pin root-to-leaf namespace as well as the files. A file handle by
            # itself does not prevent a writable ancestor from being redirected.
            foreach ($ancestor in $ancestors) { $streams.Add([Tracebolt.RustInstallerPath]::Open($ancestor, $true)) }
        }
        $expectedExecutable = Join-Path $root 'tracebolt-windows-agent.exe'
        $actualExecutable = Assert-TraceboltPlainPath $Executable
        if (![string]::Equals($actualExecutable, $expectedExecutable, [StringComparison]::OrdinalIgnoreCase)) {
            throw 'Executable must be the exact EXE alongside this installer and its package checksums.'
        }
        $allowed = @('tracebolt-windows-agent.exe','Install-Tracebolt.ps1','Uninstall-Tracebolt.ps1','Package-Preflight.ps1','README.md')
        $entries = @(Get-ChildItem -LiteralPath $root -Force)
        if ($entries.Count -ne ($allowed.Count + 1)) { throw 'Package directory must contain only the exact six package files.' }
        foreach ($entry in $entries) {
            if ($entry.PSIsContainer -or ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                ($entry.Name -cne 'SHA256SUMS.txt' -and $allowed -cnotcontains $entry.Name)) {
                throw 'Package contains an unexpected file, directory or link.'
            }
        }
        $manifestPath = Assert-TraceboltPlainPath (Join-Path $root 'SHA256SUMS.txt')
        $manifest = Open-TraceboltReadFile $manifestPath
        $streams.Add($manifest)
        if ($manifest.Length -lt 1 -or $manifest.Length -gt 8192) { throw 'Invalid package checksum manifest size.' }
        $bytes = New-Object byte[] ([int]$manifest.Length)
        $read = 0
        while ($read -lt $bytes.Length) {
            $count = $manifest.Read($bytes, $read, $bytes.Length - $read)
            if ($count -eq 0) { throw 'Truncated package checksum manifest.' }
            $read += $count
        }
        if (@($bytes | Where-Object { $_ -gt 127 }).Count) {
            throw 'Invalid package checksum manifest encoding.'
        }
        $lines = [Text.Encoding]::ASCII.GetString($bytes) -split '\r?\n'
        # Permit exactly one final line ending, never blank/interleaved records.
        if ($lines[-1] -ceq '') { $lines = $lines[0..($lines.Count - 2)] }
        if ($lines.Count -ne $allowed.Count) { throw 'Package checksums are incomplete or contain extra records.' }
        $seen = @{}
        $executableStream = $null
        foreach ($line in $lines) {
            if ($line -cnotmatch '^([a-f0-9]{64})  ([A-Za-z0-9.-]+)$') { throw 'Invalid package checksum record.' }
            $digest = $Matches[1]; $name = $Matches[2]
            if ($allowed -cnotcontains $name -or $seen.ContainsKey($name)) { throw 'Invalid package checksum allowlist.' }
            $seen[$name] = $true
            $path = Assert-TraceboltPlainPath (Join-Path $root $name)
            # Windows denies write/delete replacement until all checks, copy and
            # initialization finish. Existing open writers make this fail closed.
            $stream = Open-TraceboltReadFile $path
            $streams.Add($stream)
            $limit = if ($name -ceq 'tracebolt-windows-agent.exe') { 134217728 } else { 1048576 }
            if ($stream.Length -lt 1 -or $stream.Length -gt $limit -or (Get-TraceboltStreamHash $stream) -cne $digest) {
                throw 'Package file size or checksum mismatch.'
            }
            if ($name -ceq 'tracebolt-windows-agent.exe') {
                Assert-TraceboltAmd64Image $stream
                $executableStream = $stream
                $executableHash = $digest
            }
        }
        # Invoke the literal path actually opened/hashed, not a caller's
        # case-folded spelling in a potentially case-sensitive namespace.
        return @{ Streams = $streams; ExecutableStream = $executableStream; ExecutablePath = $expectedExecutable; SHA256 = $executableHash }
    } catch {
        foreach ($stream in $streams) { $stream.Dispose() }
        throw
    }
}

function Format-TraceboltParentAclDiagnostic(
    [ValidateSet('drive-root','program-files','program-data','other-ancestor')][string]$ParentClass,
    [string]$PrincipalSid, [int]$ForbiddenMask, [bool]$Inherited
) {
    # Finite, non-sensitive evidence only: never paths, account names, arbitrary
    # SIDs, full SDDL, error prose or values supplied by the package/manager.
    $principal = switch -CaseSensitive ($PrincipalSid) {
        'S-1-1-0' { 'everyone' }
        'S-1-5-11' { 'authenticated-users' }
        'S-1-5-32-545' { 'builtin-users' }
        'S-1-3-0' { 'creator-owner' }
        'S-1-15-2-1' { 'all-app-packages' }
        'S-1-15-2-2' { 'restricted-app-packages' }
        default { 'other-principal' }
    }
    # Include explicit generic write/all bits and concrete attribute writes.
    # Never hide a rejected generic ACE behind a misleading zero mask.
    return ('INSTALL_PARENT_ACL_UNSAFE parent={0} principal={1} forbiddenMask={2} inherited={3}' -f
        $ParentClass, $principal, ($ForbiddenMask -band 0x500d0152), [int]$Inherited)
}

function Assert-TraceboltInstallParent([string]$Path, [object]$DirectoryLease = $null) {
    $full = Assert-TraceboltPlainPath $Path -Directory
    $trusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $dangerous = [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership -bor 0x50000000
    $current = Get-Item -LiteralPath $full -Force
    while ($null -ne $current) {
        $acl = Get-Acl -LiteralPath $current.FullName
        $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
        if ($null -eq $descriptor.DiscretionaryAcl -or !($descriptor.ControlFlags -band [Security.AccessControl.ControlFlags]::DiscretionaryAclPresent)) {
            throw 'Installation parent must have an explicit discretionary ACL.'
        }
        if ($trusted -notcontains $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value) {
            throw 'Installation parents must be owned by SYSTEM, Administrators or TrustedInstaller.'
        }
        foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
            if ($rule.AccessControlType -eq 'Allow' -and !($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -and
                ($rule.FileSystemRights -band $dangerous) -and $trusted -notcontains $rule.IdentityReference.Value) {
                $matched = [int]($rule.FileSystemRights -band $dangerous)
                # Exactly the observed ProgramData / BUILTIN Users / CreateFiles
                # case, and only while THIS directory is pinned by live native
                # no-follow handles denying write/delete opens. No Boolean
                # acknowledgement, standalone relaxation or unprotected retry.
                if ($matched -eq 2 -and $rule.IdentityReference.Value -ceq 'S-1-5-32-545' -and
                    [string]::Equals($current.FullName, [Environment]::GetFolderPath('CommonApplicationData'), [StringComparison]::Ordinal) -and
                    $DirectoryLease -is [Tracebolt.InstallDirectoryLease] -and $DirectoryLease.Covers($current.FullName)) {
                    continue
                }
                $class = 'other-ancestor'
                if ([string]::Equals($current.FullName, [IO.Path]::GetPathRoot($full), [StringComparison]::OrdinalIgnoreCase)) { $class = 'drive-root' }
                elseif ([string]::Equals($current.FullName, [Environment]::GetFolderPath('ProgramFiles'), [StringComparison]::OrdinalIgnoreCase)) { $class = 'program-files' }
                elseif ([string]::Equals($current.FullName, [Environment]::GetFolderPath('CommonApplicationData'), [StringComparison]::OrdinalIgnoreCase)) { $class = 'program-data' }
                throw (Format-TraceboltParentAclDiagnostic $class $rule.IdentityReference.Value $matched $rule.IsInherited)
            }
        }
        $current = $current.Parent
    }
}

function New-TraceboltProtectedDirectory([string]$Path, [object]$DirectoryLease = $null) {
    # Unlike New-Item/Directory.CreateDirectory, this never accepts an existing
    # leaf, even if another process wins the race after absence preflight. The
    # initial protected ACL is applied atomically, before SCM or file staging.
    Initialize-TraceboltInstallerType
    if ($DirectoryLease -isnot [Tracebolt.InstallDirectoryLease]) { throw 'Protected creation requires an actual native directory lease.' }
    $DirectoryLease.Pin((Split-Path -Parent $Path))
    Assert-TraceboltInstallParent (Split-Path -Parent $Path) $DirectoryLease
    $DirectoryLease.CreateProtectedChild($Path)
}
