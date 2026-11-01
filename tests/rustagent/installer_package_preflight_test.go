package rustagent

import (
	"os"
	"strings"
	"testing"
)

// Source contracts are not execution evidence for PowerShell, Win32 or SCM.
func TestRustPackageVerificationPrecedesExecutionAndPersistentStaging(t *testing.T) {
	raw, err := os.ReadFile("../../deploy/windows-rust/Install-Tracebolt.ps1")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	last := -1
	for _, marker := range []string{
		"Assert-TraceboltInstallParent (Split-Path -Parent $bin)",
		"$package = Open-TraceboltPackage",
		"& $Executable @validationArguments",
		"if ($LASTEXITCODE -ne 0)",
		"New-TraceboltProtectedDirectory $bin",
		"New-TraceboltProtectedDirectory $data",
		"New-Service -Name",
		"[IO.FileMode]::CreateNew",
		"$package.ExecutableStream.CopyTo($output)",
		"(Get-TraceboltStreamHash $targetLock) -cne $package.SHA256",
		"& $target @initArguments",
		"Start-Service -Name",
		"foreach ($stream in $package.Streams) { $stream.Dispose() }",
	} {
		at := strings.Index(source, marker)
		if at < 0 || at <= last {
			t.Fatalf("package verification/staging ordering missing: %q", marker)
		}
		last = at
	}
	if strings.Contains(source, "Copy-Item -LiteralPath $Executable") || strings.Contains(source, "New-Item -ItemType Directory") {
		t.Fatal("installer must not reopen the verified source or adopt an existing directory")
	}
	raw, err = os.ReadFile("../../deploy/windows-rust/Package-Preflight.ps1")
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"OPEN_REPARSE_POINT", "$ancestors.Insert(0, $current.FullName)", "GetFileInformationByHandle", "Assert-TraceboltAmd64Image $stream", "$null -eq $descriptor.DiscretionaryAcl", "RootDirectory=parent.DangerousGetHandle()", "NtCreateFile(out rawChild", "$DirectoryLease.CreateProtectedChild($Path)"} {
		if !strings.Contains(string(raw), marker) {
			t.Fatalf("bounded native preflight guard missing: %q", marker)
		}
	}
}
