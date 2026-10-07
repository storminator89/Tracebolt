package windowspath

import (
	"errors"
	"reflect"
	"testing"
)

func TestCanonicalAndComponentContract(t *testing.T) {
	for _, p := range []string{`C:\`, `C:\ProgramData`, `C:\Program Files\Tracebolt\agent.exe`} {
		if !Canonical(p) {
			t.Fatal("canonical path refused")
		}
	}
	for _, p := range []string{`c:\Windows`, `\\server\share`, `C:\a\..\b`, `C:\a:stream`, `C:\a\`, `C:\a.`, `C:\a `, `C:\PROGRA~1`, "C:\\a\x00", `C:\☃`} {
		if Canonical(p) {
			t.Fatal("unsafe path accepted")
		}
	}
	for _, p := range []string{"", ".", "..", `a\b`, `C:\a`, `a/b`, `a:stream`, `a~1`} {
		if Component(p) {
			t.Fatal("noncomponent accepted")
		}
	}
	if DirectoryAccess&1 == 0 || DirectoryShare&4 != 0 {
		t.Fatal("directory does not pin against delete sharing")
	}
}
func TestCreateOnlyBindingFailureOrder(t *testing.T) {
	failure := errors.New("injected rejection")
	for _, phase := range []string{"", "before", "create", "after", "child"} {
		t.Run(phase, func(t *testing.T) {
			var calls []string
			parents := 0
			checkParent := func() error {
				parents++
				name := "before"
				if parents == 2 {
					name = "after"
				}
				calls = append(calls, name)
				if phase == name {
					return failure
				}
				return nil
			}
			err := CreatedBinding(checkParent, func() error {
				calls = append(calls, "create")
				if phase == "create" {
					return failure
				}
				return nil
			}, func() { calls = append(calls, "retain") }, func() error {
				calls = append(calls, "child")
				if phase == "child" {
					return failure
				}
				return nil
			})
			want := []string{"before", "create", "retain", "after", "child"}
			if phase == "before" {
				want = want[:1]
			}
			if phase == "create" {
				want = want[:2]
			}
			if phase == "after" {
				want = want[:4]
			}
			if !reflect.DeepEqual(calls, want) || (err != nil) != (phase != "") {
				t.Fatalf("wrong failure/retention ordering: %v", calls)
			}
		})
	}
}
