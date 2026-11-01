# Read-only package checks. Hashes establish consistency, not publisher trust.
# Dot-source only from the independently reviewed installer/package.
function Initialize-TraceboltInstallerType {
    if (!('Tracebolt.RustInstallerPath' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Tracebolt {
    public static class RustInstallerPath {
        [StructLayout(LayoutKind.Sequential)]
        private struct SecurityAttributes { public int Length; public IntPtr Descriptor; public int Inherit; }
        [StructLayout(LayoutKind.Sequential)]
        private struct FileInformation {
            public uint Attributes;
            public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
            public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
        }
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
        private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(string text, uint revision, out IntPtr descriptor, out uint size);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
        private static extern bool CreateDirectoryW(string path, ref SecurityAttributes attributes);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, ExactSpelling=true, SetLastError=true)]
        private static extern SafeFileHandle CreateFileW(string path, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
        [DllImport("kernel32.dll", ExactSpelling=true, SetLastError=true)]
        private static extern bool GetFileInformationByHandle(SafeFileHandle handle, out FileInformation information);
        [DllImport("kernel32.dll", ExactSpelling=true)]
        private static extern IntPtr LocalFree(IntPtr memory);
        public static SafeFileHandle Open(string path, bool directory) {
            // OPEN_REPARSE_POINT inspects the selected object, not a link target.
            // Share-read only denies existing/future write/delete handles.
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
        public static void CreateDirectory(string path) {
            IntPtr descriptor;
            uint size;
            if (!ConvertStringSecurityDescriptorToSecurityDescriptorW("O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", 1, out descriptor, out size))
                throw new Win32Exception(Marshal.GetLastWin32Error());
            try {
                var attributes = new SecurityAttributes { Length=Marshal.SizeOf(typeof(SecurityAttributes)), Descriptor=descriptor, Inherit=0 };
                if (!CreateDirectoryW(path, ref attributes)) throw new Win32Exception(Marshal.GetLastWin32Error());
            } finally { LocalFree(descriptor); }
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
        return @{ Streams = $streams; ExecutableStream = $executableStream; ExecutablePath = $actualExecutable; SHA256 = $executableHash }
    } catch {
        foreach ($stream in $streams) { $stream.Dispose() }
        throw
    }
}

function Assert-TraceboltInstallParent([string]$Path) {
    $full = Assert-TraceboltPlainPath $Path -Directory
    $trusted = @('S-1-5-18','S-1-5-32-544','S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
    $dangerous = [Security.AccessControl.FileSystemRights]::WriteData -bor
        [Security.AccessControl.FileSystemRights]::Delete -bor
        [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
        [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
        [Security.AccessControl.FileSystemRights]::TakeOwnership
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
                throw 'Installation parent allows non-administrative replacement or writes.'
            }
        }
        $current = $current.Parent
    }
}

function New-TraceboltProtectedDirectory([string]$Path) {
    # Unlike New-Item/Directory.CreateDirectory, this never accepts an existing
    # leaf, even if another process wins the race after absence preflight. The
    # initial protected ACL is applied atomically, before SCM or file staging.
    Initialize-TraceboltInstallerType
    Assert-TraceboltInstallParent (Split-Path -Parent $Path)
    [Tracebolt.RustInstallerPath]::CreateDirectory($Path)
}
