//go:build linux

package lanclient

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestActionLocalProtectedReadAndStableRevision(t *testing.T) {
	f := serviceActionTestFixture(t)
	uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
	f.local.policy.AgentUID = uid
	f.local.policy.AgentGID = gid
	dirpath := t.TempDir()
	raw, _ := json.Marshal(f.local.policy)
	p := filepath.Join(dirpath, "action-client.json")
	if e := os.WriteFile(p, raw, 0640); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(p, 0640); e != nil {
		t.Fatal(e)
	}
	dir, e := os.Open(dirpath)
	if e != nil {
		t.Fatal(e)
	}
	defer dir.Close()
	a, e := readActionLocalFile(dir, f.s.material, uid, gid, uid)
	if e != nil {
		t.Fatal(e)
	}
	b, e := readActionLocalFile(dir, f.s.material, uid, gid, uid)
	if e != nil || a.revision != b.revision {
		t.Fatal("read renewed revision", e)
	}
	replacement := filepath.Join(dirpath, "next")
	if e := os.WriteFile(replacement, raw, 0640); e != nil {
		t.Fatal(e)
	}
	if e := os.Chmod(replacement, 0640); e != nil {
		t.Fatal(e)
	}
	if e := os.Rename(replacement, p); e != nil {
		t.Fatal(e)
	}
	c, e := readActionLocalFile(dir, f.s.material, uid, gid, uid)
	if e != nil || c.revision == a.revision {
		t.Fatal("same bytes replacement missed", e)
	}
}
func TestActionLocalRejectsUnsafeFixtures(t *testing.T) {
	for _, kind := range []string{"missing", "mode", "symlink", "hardlink", "directory", "wrong_owner", "wrong_group", "noncanonical", "profile", "disabled"} {
		t.Run(kind, func(t *testing.T) {
			f := serviceActionTestFixture(t)
			uid, gid := uint32(os.Geteuid()), uint32(os.Getegid())
			f.local.policy.AgentUID = uid
			f.local.policy.AgentGID = gid
			if kind == "profile" {
				f.local.policy.TransportProfile = "http-test"
			}
			if kind == "disabled" {
				f.local.policy.Enabled = false
			}
			raw, _ := json.Marshal(f.local.policy)
			if kind == "noncanonical" {
				raw = append(raw, ' ')
			}
			dirpath := t.TempDir()
			p := filepath.Join(dirpath, "action-client.json")
			if kind != "missing" {
				if e := os.WriteFile(p, raw, 0640); e != nil {
					t.Fatal(e)
				}
				os.Chmod(p, 0640)
			}
			switch kind {
			case "mode":
				os.Chmod(p, 0660)
			case "symlink":
				os.Rename(p, p+".original")
				os.Symlink(p+".original", p)
			case "hardlink":
				if e := os.Link(p, p+".other"); e != nil {
					t.Fatal(e)
				}
			case "directory":
				os.Remove(p)
				os.Mkdir(p, 0700)
			case "wrong_group":
				gid++
			}
			dir, e := os.Open(dirpath)
			if e != nil {
				t.Fatal(e)
			}
			defer dir.Close()
			owner := uid
			if kind == "wrong_owner" {
				owner++
			}
			_, e = readActionLocalFile(dir, f.s.material, uid, gid, owner)
			if e == nil {
				t.Fatal("accepted")
			}
			if (kind == "missing" || kind == "disabled") && !errors.Is(e, errActionDisabled) {
				t.Fatal(e)
			}
		})
	}
}
