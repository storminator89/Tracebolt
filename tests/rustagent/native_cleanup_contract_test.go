package rustagent

import (
	"os"
	"strings"
	"testing"
)

// Source-order regression only: no PowerShell, process, SCM or native operation
// is executed. Windows acceptance must still verify the actual cleanup behavior.
func TestNativeFixtureExitPrecedesExecutableRemoval(t *testing.T) {
	raw, err := os.ReadFile("Run-NativeAcceptance.ps1")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	start := strings.Index(source, "if ($null -ne $fixture) {")
	if start < 0 {
		t.Fatal("fixture cleanup guard is missing")
	}
	cleanup := source[start:]
	last := -1
	for _, marker := range []string{
		"if (!$fixture.HasExited) { Stop-Process -InputObject $fixture -Force }",
		"if (!$fixture.WaitForExit(10000)) { throw 'Loopback fixture did not exit within the cleanup deadline.' }",
		"} finally { $fixture.Dispose() }",
		"Remove-Item -LiteralPath $binaryDirectory -Recurse -Force",
		"Remove-Item -LiteralPath $dataDirectory -Recurse -Force",
		"Remove-Item -LiteralPath $temporary -Recurse -Force",
	} {
		at := strings.Index(cleanup, marker)
		if at < 0 || at <= last {
			t.Fatalf("bounded fixture cleanup ordering missing: %q", marker)
		}
		last = at
	}
	if strings.Contains(cleanup, "Stop-Process -Id") {
		t.Fatal("cleanup must bind termination to the original process object")
	}
	for _, forbidden := range []string{"Set-Acl", "takeown", "icacls", "WaitForExit()", "-ErrorAction SilentlyContinue"} {
		if strings.Contains(cleanup[:last], forbidden) {
			t.Fatalf("fixture cleanup must not bypass failures or wait without a bound: %q", forbidden)
		}
	}
}
