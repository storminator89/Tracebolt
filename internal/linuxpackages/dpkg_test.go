package linuxpackages

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestDpkgSourceMappingsAndPrivacy(t *testing.T) {
	data, err := os.ReadFile("testdata/synthetic.status")
	if err != nil {
		t.Fatal(err)
	}
	rows, err := ParseDpkgStatus(context.Background(), strings.NewReader(string(data)))
	if err != nil || len(rows) != 3 {
		t.Fatalf("rows=%d error=%v", len(rows), err)
	}
	if rows[0].SourceMapping != "source-field" || rows[0].SourceVersion != "1:2.0~rc1-1+deb13u1" || rows[0].Version != "1:2.0~rc1-1+deb13u1+b1" || rows[0].InstallState != "installed" {
		t.Fatal("explicit source version or install state lost")
	}
	if rows[1].SourcePackage != "tracebolt-fixture-source" || rows[1].SourceVersion != rows[1].Version || rows[1].SourceMapping != "source-field" || rows[1].Architecture != "arm64" {
		t.Fatal("explicit source with default version/foreign arch lost")
	}
	if rows[2].SourcePackage != rows[2].Name || rows[2].SourceVersion != "2.0-1+b9" || rows[2].SourceMapping != "binary-default" || rows[2].InstallState != "incomplete" {
		t.Fatal("default mapping guessed a different source version")
	}
	encoded, _ := json.Marshal(rows)
	for _, forbidden := range []string{"private", "example.invalid", "Maintainer", "Description", "origin", "sha256", "digest", "verified"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatal("unselected data or authority leaked")
		}
	}
	changed := strings.ReplaceAll(string(data), "private", "different")
	other, err := ParseDpkgStatus(context.Background(), strings.NewReader(changed))
	if err != nil || !reflect.DeepEqual(rows, other) {
		t.Fatal("ignored content changed exported representation")
	}
}

const validStatus = "Package: tracebolt-fixture\nStatus: install ok installed\nVersion: 1.0-1\nArchitecture: amd64\n"

func TestDpkgFailuresHaveNoPrefix(t *testing.T) {
	for name, input := range map[string]string{
		"empty": "", "duplicate field": validStatus + "version: 2.0-1\n",
		"duplicate identity":          validStatus + "\n" + validStatus,
		"selected continuation":       validStatus + "Source: fixture\n (1.0)\n",
		"missing source value":        validStatus + "Source:\n",
		"malformed source":            validStatus + "Source: fixture (1.0) extra\n",
		"bad source version":          validStatus + "Source: fixture (invalid)\n",
		"injection":                   strings.ReplaceAll(validStatus, "1.0-1", "1.0;command"),
		"one character name":          strings.ReplaceAll(validStatus, "tracebolt-fixture", "a"),
		"one character source":        validStatus + "Source: a\n",
		"nonbinary architecture":      strings.ReplaceAll(validStatus, "amd64", "source"),
		"wildcard architecture":       strings.ReplaceAll(validStatus, "amd64", "any"),
		"os wildcard architecture":    strings.ReplaceAll(validStatus, "amd64", "linux-any"),
		"cpu wildcard architecture":   strings.ReplaceAll(validStatus, "amd64", "any-amd64"),
		"tuple wildcard architecture": strings.ReplaceAll(validStatus, "amd64", "musl-any-any"),
		"overlong line":               validStatus + "Description: " + strings.Repeat("x", MaxDpkgLine),
	} {
		t.Run(name, func(t *testing.T) {
			rows, err := ParseDpkgStatus(context.Background(), strings.NewReader(input))
			if err == nil || rows != nil {
				t.Fatal("invalid source retained rows")
			}
			if strings.Contains(err.Error(), "command") {
				t.Fatal("source contents leaked in error")
			}
		})
	}
	for _, reader := range []io.Reader{nil, brokenReader{}, io.MultiReader(strings.NewReader(validStatus), brokenReader{})} {
		rows, err := ParseDpkgStatus(context.Background(), reader)
		if err != ErrDpkgRead || rows != nil {
			t.Fatal("read failure leaked prefix/raw error")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rows, err := ParseDpkgStatus(ctx, strings.NewReader(validStatus)); err != ErrDpkgRead || rows != nil {
		t.Fatal("cancellation ignored")
	}
}

func TestDpkgEmptyVersusResidualOnly(t *testing.T) {
	if rows, err := ParseDpkgStatus(context.Background(), strings.NewReader("")); rows != nil || err != ErrDpkgEmpty {
		t.Fatal("absent database became empty success")
	}
	rows, err := ParseDpkgStatus(context.Background(), strings.NewReader("Package: tracebolt-residual\nStatus: deinstall ok config-files\n"))
	if err != nil || rows == nil || len(rows) != 0 {
		t.Fatal("successfully parsed residual-only scope became unavailable")
	}
}

func TestDpkgByteBound(t *testing.T) {
	input := validStatus + "Description: ignored\n" + strings.Repeat(" "+strings.Repeat("x", 1022)+"\n", MaxDpkgBytes/1024+1)
	if rows, err := ParseDpkgStatus(context.Background(), strings.NewReader(input)); err != ErrDpkgLimit || rows != nil {
		t.Fatal("byte limit failed")
	}
}

func FuzzDpkgNoPrefixOnError(f *testing.F) {
	f.Add(validStatus)
	f.Add(validStatus + "Source: fixture-source (1:1.0~rc1-2)\n")
	f.Add("Package: broken\n")
	f.Fuzz(func(t *testing.T, input string) {
		rows, err := ParseDpkgStatus(context.Background(), strings.NewReader(input))
		if err != nil && rows != nil {
			t.Fatal("error retained parsed prefix")
		}
	})
}
