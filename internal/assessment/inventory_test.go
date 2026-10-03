package assessment

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

const syntheticStatus = `Package: tracebolt-fixture-binary
Status: install ok installed
Version: 1:2.0-1+deb13u1+b1
Architecture: amd64
Source: tracebolt-fixture-source (1:2.0-1+deb13u1)
Maintainer: private-synthetic-maintainer@example.invalid
Description: synthetic description not retained
 with a continuation

Package: tracebolt-fixture-residual
Status: deinstall ok config-files
Version: 9.0-1
Architecture: all

Package: tracebolt-fixture-incomplete
Status: install reinstreq half-installed
Version: 1.0~rc1-1
Architecture: arm64
`

func TestDpkgSelectedFieldsAndInstallStates(t *testing.T) {
	packages, digest, err := ParseDpkgStatus(context.Background(), strings.NewReader(syntheticStatus))
	if err != nil {
		t.Fatal(err)
	}
	if len(packages) != 2 || len(digest) != 64 {
		t.Fatal("incorrect bounded inventory shape")
	}
	first := packages[0]
	if first.SourcePackage != "tracebolt-fixture-source" || first.SourceVersion != "1:2.0-1+deb13u1" || first.Version != "1:2.0-1+deb13u1+b1" {
		t.Fatal("source/binary mapping lost")
	}
	if first.InstallState != "installed" || packages[1].InstallState != "incomplete" || packages[1].Architecture != "arm64" {
		t.Fatal("state/foreign architecture lost")
	}
	if first.Origin.InstalledArtifactVerified || first.Origin.VerifiedMetadata {
		t.Fatal("dpkg record cannot authenticate origin")
	}
	data, _ := json.Marshal(packages)
	if strings.Contains(string(data), "maintainer") || strings.Contains(string(data), "description") || strings.Contains(string(data), "example.invalid") {
		t.Fatal("unselected fields leaked")
	}
}
func TestDpkgSourceDefaults(t *testing.T) {
	for _, source := range []string{"", "Source: tracebolt-fixture-source\n"} {
		data := "Package: tracebolt-fixture-binary\nStatus: hold ok installed\nVersion: 1.0-1\nArchitecture: all\n" + source
		rows, _, err := ParseDpkgStatus(context.Background(), strings.NewReader(data))
		if err != nil {
			t.Fatal(err)
		}
		wantName := "tracebolt-fixture-binary"
		if source != "" {
			wantName = "tracebolt-fixture-source"
		}
		if rows[0].SourceVersion != "1.0-1" || rows[0].SourcePackage != wantName {
			t.Fatal("dpkg default source mapping incorrect")
		}
	}
}
func TestDpkgRejectsAmbiguityAndLimits(t *testing.T) {
	prefix := "Package: tracebolt-fixture-binary\nStatus: install ok installed\nVersion: 1.0-1\nArchitecture: amd64\n"
	cases := map[string]string{
		"empty":                                "",
		"invalid utf8":                         prefix + "Description: \xff\n",
		"duplicate selected":                   prefix + "Version: 2.0-1\n",
		"duplicate ignored":                    prefix + "Maintainer: ignored\nMaintainer: ignored again\n",
		"duplicate differently cased selected": prefix + "version: 2.0-1\n",
		"selected continuation":                prefix + "Source: tracebolt-fixture-source\n (1.0-1)\n",
		"orphan continuation":                  " continuation\n" + prefix,
		"duplicate package":                    prefix + "\n" + prefix,
		"missing version":                      strings.ReplaceAll(prefix, "Version: 1.0-1\n", ""),
		"invalid status":                       strings.ReplaceAll(prefix, "install ok installed", "install ok imagined"),
		"invalid source":                       prefix + "Source: tracebolt-fixture-source (nonsense)\n",
		"invalid version":                      strings.ReplaceAll(prefix, "1.0-1", "1.0;touch /tmp/never"),
		"overlong line":                        prefix + "Description: " + strings.Repeat("x", MaxInventoryLine) + "\n",
		"too many fields":                      prefix + strings.Repeat("X: value\n", MaxInventoryFields+1),
		"nul":                                  prefix + "Description: \x00\n",
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			rows, digest, err := ParseDpkgStatus(context.Background(), strings.NewReader(input))
			if err == nil {
				t.Fatal("accepted malformed inventory")
			}
			if rows != nil || digest != "" {
				t.Fatal("retained malformed prefix")
			}
			if strings.Contains(err.Error(), "touch") || strings.Contains(err.Error(), "ignored") {
				t.Fatal("raw contents leaked")
			}
		})
	}
}
func TestDpkgTotalByteBound(t *testing.T) {
	input := "Package: fixture\nStatus: install ok installed\nVersion: 1.0\nArchitecture: all\nDescription: ignored\n" + strings.Repeat(" "+strings.Repeat("x", 1022)+"\n", MaxInventoryBytes/1024+1)
	if _, _, err := ParseDpkgStatus(context.Background(), strings.NewReader(input)); !errors.Is(err, ErrInventoryLimit) {
		t.Fatalf("expected byte limit, got %v", err)
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) {
	return 0, errors.New("private file body must not escape")
}
func TestDpkgReadFailureAndCancellation(t *testing.T) {
	if _, _, err := ParseDpkgStatus(context.Background(), brokenReader{}); err != ErrInventoryRead {
		t.Fatalf("unsanitized read error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := ParseDpkgStatus(ctx, strings.NewReader(syntheticStatus)); err != ErrInventoryRead {
		t.Fatal("ignored cancellation")
	}
}
func TestLocalMissingDatabaseIsUnavailable(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only fixed dpkg database acceptance")
	}
	// Environment-dependent read-only acceptance; no real package rows are printed.
	// On a full system the parser tests remain synthetic, and this absence test skips.
	if _, err := os.Lstat("/var/lib/dpkg/status"); !errors.Is(err, os.ErrNotExist) {
		t.Skip("absence-only acceptance: database exists or different error")
	}
	result := (LocalDebianInventory{}).Collect(context.Background(), testPlatform(), testNow())
	if result.Quality.Coverage != Unknown || result.InstalledCount != nil || len(result.Packages) != 0 || !contains(result.Quality.ReasonCodes, "package_database_unavailable") {
		t.Fatal("missing database became empty success")
	}
	t.Log("verified missing-database path; no installed inventory or native update assessment established")
}
func TestOtherPlatformsUnimplemented(t *testing.T) {
	for _, platform := range []Platform{{OS: "windows"}, {OS: "macos"}, {OS: "linux", Distribution: "linuxmint", Version: "22", Codename: "trixie"}, {OS: "linux", Distribution: "ubuntu", Version: "24.04", Codename: "noble"}} {
		result := (LocalDebianInventory{}).Collect(context.Background(), platform, testNow())
		if result.Quality.Coverage != Unknown || result.InstalledCount != nil || !contains(result.Quality.ReasonCodes, "inventory_adapter_unimplemented") {
			t.Fatal("unsupported OS silently counted")
		}
	}
	updates := UnimplementedUpdates(testNow())
	if updates.Quality.Coverage != Unknown || updates.OfferedCount != nil || updates.Source != nil {
		t.Fatal("unimplemented updates became healthy zero")
	}
}
func TestResidualOnlyIsSuccessfullyEnumeratedZero(t *testing.T) {
	rows, _, err := ParseDpkgStatus(context.Background(), strings.NewReader("Package: tracebolt-residual\nStatus: deinstall ok config-files\n"))
	if err != nil || len(rows) != 0 {
		t.Fatal("residual config counted as installed")
	}
}
func FuzzDpkgStatusNeverLeaksPrefix(f *testing.F) {
	f.Add(syntheticStatus)
	f.Add("Package: broken\n")
	f.Fuzz(func(t *testing.T, input string) {
		rows, digest, err := ParseDpkgStatus(context.Background(), strings.NewReader(input))
		if err != nil && (rows != nil || digest != "") {
			t.Fatal("error returned a partial successful prefix")
		}
	})
}
func testNow() time.Time { return time.Date(2026, 10, 3, 15, 0, 0, 0, time.UTC) }
func testPlatform() Platform {
	return Platform{OS: "linux", Distribution: "debian", Version: "13", Codename: "trixie", Architecture: "amd64", CollectionScope: "restricted_environment"}
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

var _ io.Reader = brokenReader{}
