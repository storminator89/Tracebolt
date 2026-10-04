package linuxpackages

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

func TestReleaseFixturesAndPrivacy(t *testing.T) {
	for _, tc := range []struct {
		file string
		want ReleaseTarget
	}{{"debian13.os-release", Debian13}, {"ubuntu2404.os-release", Ubuntu2404}} {
		t.Run(tc.file, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + tc.file)
			if err != nil {
				t.Fatal(err)
			}
			r, err := ParseOSRelease(context.Background(), strings.NewReader(string(data)))
			if err != nil || r.Target() != tc.want {
				t.Fatalf("target=%s err=%v", r.Target(), err)
			}
			encoded, _ := json.Marshal(r)
			for _, forbidden := range []string{"private", "PRETTY_NAME", "ID_LIKE", "HOME_URL", "UBUNTU_CODENAME", "GNU/Linux", "digest", "sha256"} {
				if strings.Contains(string(encoded), forbidden) {
					t.Fatal("unselected metadata leaked")
				}
			}
		})
	}
}

func TestReleaseTargetIsExact(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  ReleaseTarget
	}{
		{"ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n", Debian13},
		{"ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=noble\n", Ubuntu2404},
		{"ID=linuxmint\nVERSION_ID=24.04\nVERSION_CODENAME=noble\nID_LIKE=ubuntu\n", Unsupported},
		{"ID=debian\nVERSION_ID=12\nVERSION_CODENAME=bookworm\n", Unsupported},
		{"ID=debian\nVERSION_ID=13\nVERSION_CODENAME=bookworm\n", Inconsistent},
		{"ID=debian\nVERSION_ID=13.1\nVERSION_CODENAME=trixie\n", Inconsistent},
		{"ID=ubuntu\nVERSION_ID=24.04.1\nVERSION_CODENAME=noble\n", Inconsistent},
		{"ID=ubuntu\nVERSION_ID=24.04\nVERSION_CODENAME=trixie\n", Inconsistent},
		{"NAME='Debian 13 trixie'\nID_LIKE=debian\n", Incomplete},
		{"ID=debian\nVERSION_ID=13\n", Incomplete},
		{"ID=ubuntu\nVERSION_ID=24.04\nUBUNTU_CODENAME=noble\n", Incomplete},
		{"ID=\nVERSION_ID=13\nVERSION_CODENAME=trixie\n", Incomplete},
		{"# no facts\n\n", Incomplete},
		{"", Incomplete},
	} {
		r, err := ParseOSRelease(context.Background(), strings.NewReader(tc.input))
		if err != nil || r.Target() != tc.want {
			t.Errorf("target=%s want=%s err=%v", r.Target(), tc.want, err)
		}
	}
}

func TestReleaseAbsentAndEmptyRemainDistinct(t *testing.T) {
	r, err := ParseOSRelease(context.Background(), strings.NewReader("ID=\nVERSION_ID=''\n"))
	if err != nil || r.ID == nil || *r.ID != "" || r.VersionID == nil || *r.VersionID != "" || r.VersionCodename != nil {
		t.Fatal("missing and empty fields conflated")
	}
	b, _ := json.Marshal(r)
	if string(b) != `{"id":"","versionId":"","versionCodename":null}` {
		t.Fatal("incorrect explicit null encoding")
	}
}

func TestReleaseLiteralSyntax(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"debian", "debian"}, {"'debian'", "debian"}, {`"debian"`, "debian"},
		{`de\bian`, "debian"}, {`"a\"b"`, `a"b`}, {`"a\$b"`, "a$b"},
		{`"a\` + "`" + `b"`, "a`b"}, {`"a\\b"`, `a\b`},
		{`"a\qb"`, `a\qb`}, {`'$(ignored)'`, "$(ignored)"},
	} {
		got, ok := releaseLiteral(tc.input)
		if !ok || got != tc.want {
			t.Errorf("literal did not preserve documented quoting")
		}
	}
	for _, input := range []string{`"de""bian"`, `de'bian'`, "debian # comment", `$(command)`, "`command`", `"$ID"`, `'unclosed`, "debian\\", "a;b"} {
		if _, ok := releaseLiteral(input); ok {
			t.Error("accepted nonliteral or ambiguous assignment")
		}
	}
}

func TestReleaseRejectsMalformedWithoutPrefix(t *testing.T) {
	prefix := "ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n"
	for name, suffix := range map[string]string{
		"duplicate selected": "ID=ubuntu\n", "duplicate ignored": "NAME=a\nNAME=b\n",
		"bad key": "9ID=debian\n", "key whitespace": "ID =debian\n",
		"no assignment": "export VARIABLE\n", "nul": "NAME=bad\x00\n", "crlf": "NAME=value\r\n",
		"invalid utf8": "NAME=\xff\n", "control": "NAME=\x1b\n",
		"expansion": "NAME=$(command)\n", "inline comment": "NAME=value # ignored?\n",
		"multiline": "NAME=\"hello\nworld\"\n", "selected uppercase": "ID2=ignored\nVERSION_CODENAME=Noble\n",
	} {
		t.Run(name, func(t *testing.T) {
			r, err := ParseOSRelease(context.Background(), strings.NewReader(prefix+suffix))
			if err == nil || r.ID != nil || r.VersionID != nil || r.VersionCodename != nil {
				t.Fatal("malformed source returned facts")
			}
		})
	}
	for _, input := range []string{"ID=Debian\n", `ID="de\bian"`, "VERSION_ID='24.04 LTS'\n", "VERSION_CODENAME='noble;command'\n"} {
		if _, err := ParseOSRelease(context.Background(), strings.NewReader(input)); err != ErrReleaseInvalid {
			t.Fatal("accepted invalid selected identifier")
		}
	}
}

func TestReleaseBoundsAndReadErrors(t *testing.T) {
	keys := strings.Builder{}
	for i := 0; i <= MaxOSReleaseKeys; i++ {
		fmt.Fprintf(&keys, "X%d=value\n", i)
	}
	for _, input := range []string{
		strings.Repeat("#\n", MaxOSReleaseBytes/2+1),
		"#" + strings.Repeat("x", MaxOSReleaseLine),
		"ID=" + strings.Repeat("x", MaxReleaseValue+1), keys.String(),
	} {
		if _, err := ParseOSRelease(context.Background(), strings.NewReader(input)); err != ErrReleaseLimit {
			t.Fatalf("wanted limit failure; got %v", err)
		}
	}
	for _, input := range []string{"#" + strings.Repeat("x", MaxOSReleaseLine-1), "ID=" + strings.Repeat("x", MaxReleaseValue), strings.Repeat("#\n", MaxOSReleaseBytes/2)} {
		if _, err := ParseOSRelease(context.Background(), strings.NewReader(input)); err != nil {
			t.Fatalf("exact bound rejected: %v", err)
		}
	}
	for _, reader := range []io.Reader{nil, brokenReader{}, io.MultiReader(strings.NewReader("ID=debian\n"), brokenReader{})} {
		r, err := ParseOSRelease(context.Background(), reader)
		if err != ErrReleaseRead || r.ID != nil {
			t.Fatal("read error leaked a prefix or raw error")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ParseOSRelease(ctx, strings.NewReader("ID=debian")); err != ErrReleaseRead {
		t.Fatal("cancellation ignored")
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) {
	return 0, errors.New("private synthetic source must not escape")
}

func FuzzOSReleaseNoPrefixOnError(f *testing.F) {
	f.Add("ID=debian\nVERSION_ID=13\nVERSION_CODENAME=trixie\n")
	f.Add("ID=''\n")
	f.Add("ID=debian\nID=ubuntu\n")
	f.Fuzz(func(t *testing.T, input string) {
		r, err := ParseOSRelease(context.Background(), strings.NewReader(input))
		if err != nil && (r.ID != nil || r.VersionID != nil || r.VersionCodename != nil) {
			t.Fatal("error retained a parsed prefix")
		}
		for _, value := range []*string{r.ID, r.VersionID, r.VersionCodename} {
			if value != nil && (len(*value) > MaxReleaseValue || !validReleaseIdentifier(*value)) {
				t.Fatal("unvalidated selected value")
			}
		}
	})
}
