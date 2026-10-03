//go:build linux

package agentinstall

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func artifactDigest(t *testing.T, path string) string {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func TestVerifiedBinaryCopyAndSourceIntegrity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lan-agent")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", path, "../../cmd/lan-agent")
	if cmd.Run() != nil {
		t.Fatal("native binary fixture build")
	}
	digest := artifactDigest(t, path)
	v, e := VerifyBinary(context.Background(), path, digest, SenderBinary)
	if e != nil {
		t.Fatal("valid native artifact rejected", e)
	}
	defer v.Close()
	var copied bytes.Buffer
	if v.CopyVerified(context.Background(), &copied) != nil {
		t.Fatal("verified staging failed")
	}
	sum := sha256.Sum256(copied.Bytes())
	if hex.EncodeToString(sum[:]) != digest {
		t.Fatal("copied digest changed")
	}
	if bad, e := VerifyBinary(context.Background(), path, strings.Repeat("1", 64), SenderBinary); e == nil {
		bad.Close()
		t.Fatal("wrong digest accepted")
	}
	if bad, e := VerifyBinary(context.Background(), path, digest, EnrollmentBinary); e == nil {
		bad.Close()
		t.Fatal("wrong binary role accepted")
	}
	source := filepath.Join(t.TempDir(), "source.fixture")
	if os.WriteFile(source, []byte("source archive bytes are hashed, never extracted"), 0600) != nil {
		t.Fatal("fixture")
	}
	if VerifySource(context.Background(), source, artifactDigest(t, source)) != nil {
		t.Fatal("source digest rejected")
	}
	if VerifySource(context.Background(), source, strings.Repeat("2", 64)) == nil {
		t.Fatal("source mismatch accepted")
	}
}
func TestArtifactRejectsUnsafeAndChangedSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "plain")
	if os.WriteFile(path, []byte("not executable"), 0600) != nil {
		t.Fatal("fixture")
	}
	digest := artifactDigest(t, path)
	if v, e := VerifyBinary(context.Background(), path, digest, SenderBinary); e == nil {
		v.Close()
		t.Fatal("non-native bytes accepted")
	}
	link := filepath.Join(t.TempDir(), "link")
	if os.Symlink(path, link) != nil {
		t.Fatal("fixture")
	}
	if VerifySource(context.Background(), link, digest) == nil {
		t.Fatal("symlink accepted")
	}
	if os.Chmod(path, 0666) != nil {
		t.Fatal("fixture")
	}
	if VerifySource(context.Background(), path, digest) == nil {
		t.Fatal("shared writable artifact accepted")
	}
}
