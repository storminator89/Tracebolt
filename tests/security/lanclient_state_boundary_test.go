package security_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"localrmm/internal/lanclientstate"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIndependentSenderStateLockExactBytesAndSequence(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only sender state")
	}
	dir := filepath.Join(t.TempDir(), "private")
	binding := strings.Repeat("a", 64)
	state, err := lanclientstate.Open(dir, binding)
	if err != nil {
		t.Fatal(err)
	}
	if second, e := lanclientstate.Open(dir, binding); !errors.Is(e, lanclientstate.ErrLocked) {
		if second != nil {
			second.Close()
		}
		t.Fatal("second writer not rejected")
	}
	body := []byte("{\n  \"synthetic\": \"private-observation-marker\"\n}\n")
	pending, err := state.Stage(1, body)
	if err != nil {
		t.Fatal(err)
	}
	copy := pending.Body()
	copy[0] = '!'
	if string(pending.Body()) != string(body) {
		t.Fatal("consumer changed retained bytes")
	}
	for _, value := range []any{pending, &pending, state, *state} {
		encoded, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(encoded), "private-observation-marker") {
			t.Fatal("state JSON leaked body")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			if strings.Contains(fmt.Sprintf(format, value), "private-observation-marker") {
				t.Fatal("state formatting leaked body")
			}
		}
	}
	if err = state.Close(); err != nil {
		t.Fatal(err)
	}
	state, err = lanclientstate.Open(dir, binding)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	again, err := state.Pending()
	if err != nil || again == nil || again.Sequence != 1 || again.Digest != pending.Digest || string(again.Body()) != string(body) {
		t.Fatal("restart changed pending bytes or sequence")
	}
	if _, err = state.Stage(2, body); !errors.Is(err, lanclientstate.ErrPending) {
		t.Fatal("new sample replaced unresolved request")
	}
	if err = state.Acknowledge(strings.Repeat("b", 64)); !errors.Is(err, lanclientstate.ErrDigest) {
		t.Fatal("wrong receipt digest cleared state")
	}
	if err = state.Acknowledge(pending.Digest); err != nil {
		t.Fatal(err)
	}
	if sequence, e := state.NextSequence(); e != nil || sequence != 2 {
		t.Fatal("acknowledgment reset or reused sequence")
	}
}

func TestIndependentSenderStateDoesNotAdoptOrCleanUnvalidatedDirectory(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux-only sender state")
	}
	for _, scenario := range []string{"fresh unrelated directory", "different binding", "corrupt ledger"} {
		t.Run(scenario, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "private")
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			binding := strings.Repeat("a", 64)
			if scenario != "fresh unrelated directory" {
				state, err := lanclientstate.Open(dir, binding)
				if err != nil {
					t.Fatal(err)
				}
				if err = state.Close(); err != nil {
					t.Fatal(err)
				}
			}
			marker := filepath.Join(dir, ".state.tmp")
			original := []byte("synthetic preexisting file; never real user data")
			if err := os.WriteFile(marker, original, 0600); err != nil {
				t.Fatal(err)
			}
			if scenario == "different binding" {
				binding = strings.Repeat("b", 64)
			}
			if scenario == "corrupt ledger" {
				if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(`{"invalid":true}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			state, err := lanclientstate.Open(dir, binding)
			if state != nil {
				_ = state.Close()
			}
			retained, readErr := os.ReadFile(marker)
			if readErr != nil || string(retained) != string(original) {
				t.Fatal("rejected or unvalidated state path removed preexisting temporary file")
			}
			if err == nil {
				t.Fatal("nonempty unrelated directory was adopted as sender state")
			}
		})
	}
}
