//go:build linux

package packageupdatestore

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"localrmm/internal/packageupdate"
)

func TestProtectedPathRejectsPermissionsLinksAndSidecars(t *testing.T) {
	for _, kind := range []string{"public-file", "hardlink", "file-symlink", "directory-symlink", "public-directory", "journal-symlink", "foreign-wal", "rollback-journal", "wal-header"} {
		t.Run(kind, func(t *testing.T) {
			s, path, r, _, _ := fixture(t)
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			openPath := path
			switch kind {
			case "public-file":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			case "file-symlink":
				openPath = path + ".link"
				if err := os.Symlink(path, openPath); err != nil {
					t.Fatal(err)
				}
			case "directory-symlink":
				link := filepath.Join(filepath.Dir(filepath.Dir(path)), "link")
				if err := os.Symlink(filepath.Dir(path), link); err != nil {
					t.Fatal(err)
				}
				openPath = filepath.Join(link, filepath.Base(path))
			case "public-directory":
				if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
					t.Fatal(err)
				}
			case "journal-symlink":
				if err := os.Symlink(path, path+"-journal"); err != nil {
					t.Fatal(err)
				}
			case "foreign-wal":
				if err := os.WriteFile(path+"-wal", nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "rollback-journal":
				if err := os.WriteFile(path+"-journal", nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "wal-header":
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				raw[18], raw[19] = 2, 2
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if bad, err := OpenExisting(ctx, openPath, r.Binding); err == nil {
				bad.Close()
				t.Fatal("accepted unsafe path")
			}
			if _, err := Create(ctx, openPath, r.Binding, now); err == nil {
				t.Fatal("adopted unsafe existing state")
			}
			if kind == "public-file" {
				info, _ := os.Lstat(path)
				if info.Mode().Perm() != 0644 {
					t.Fatal("silently repaired file permissions")
				}
			}
			if kind == "public-directory" {
				info, _ := os.Lstat(filepath.Dir(path))
				if info.Mode().Perm() != 0755 {
					t.Fatal("silently repaired directory permissions")
				}
			}
		})
	}
}
func TestCreateRejectsOrphanSidecarAndMissingDirectory(t *testing.T) {
	r, _, _ := fixtureRecord(t)
	for _, suffix := range []string{"-journal", "-wal", "-shm"} {
		dir := t.TempDir()
		path := filepath.Join(dir, "fixture.sqlite")
		if err := os.WriteFile(path+suffix, nil, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Create(ctx, path, r.Binding, now); err == nil {
			t.Fatal("adopted orphan", suffix)
		}
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatal("created DB beside orphan")
		}
	}
	path := filepath.Join(t.TempDir(), "absent", "fixture.sqlite")
	if _, err := Create(ctx, path, r.Binding, now); err == nil {
		t.Fatal("silently provisioned directory")
	}
}
func TestExclusiveHandleAndPathReplacementFence(t *testing.T) {
	s, path, r, _, _ := fixture(t)
	if other, err := OpenExisting(ctx, path, r.Binding); !errors.Is(err, ErrLocked) {
		if other != nil {
			other.Close()
		}
		t.Fatal("concurrent store session", err)
	}
	original := path + ".original"
	if err := os.Rename(path, original); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(ctx, r.Binding); !errors.Is(err, packageupdate.ErrUncertain) {
		t.Fatal("accepted replaced file", err)
	}
	if err := s.Close(); !errors.Is(err, packageupdate.ErrUncertain) {
		t.Fatal("cleared uncertain fence", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(original, path); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenExisting(ctx, path, r.Binding); !errors.Is(err, packageupdate.ErrUncertain) {
		t.Fatal("original guard lost", err)
	}
}
func TestDirectoryReplacementIsNotAdopted(t *testing.T) {
	s, path, r, _, _ := fixture(t)
	dir := filepath.Dir(path)
	moved := dir + "-moved"
	if err := os.Rename(dir, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(moved, filepath.Base(path)), path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Open(ctx, r.Binding); !errors.Is(err, packageupdate.ErrUncertain) {
		t.Fatal("adopted replaced parent directory", err)
	}
	if err := s.Close(); !errors.Is(err, packageupdate.ErrUncertain) {
		t.Fatal(err)
	}
	if _, err := OpenExisting(ctx, path, r.Binding); !errors.Is(err, packageupdate.ErrUncertain) {
		t.Fatal("lost guard after directory replacement", err)
	}
}
