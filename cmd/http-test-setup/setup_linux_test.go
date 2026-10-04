//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"localrmm/internal/enrollmentconfig"
	"localrmm/internal/enrollmentissuer"
	"localrmm/internal/lanconfig"
	"localrmm/internal/operatorauth"
)

func fixturePassword() []byte { return bytes.Repeat([]byte{'x'}, 20) }
func fixtureTime() time.Time  { return time.Date(2026, 10, 4, 7, 0, 0, 0, time.UTC) }
func fixtureFiles(t *testing.T) []materialFile {
	t.Helper()
	password := fixturePassword()
	defer clear(password)
	files, e := generate("192.168.1.50", password, rand.New(rand.NewSource(81)), fixtureTime())
	if e != nil {
		t.Fatal("synthetic material generation failed")
	}
	t.Cleanup(func() { clearFiles(files) })
	return files
}
func temporaryParent(t *testing.T) (string, int) {
	t.Helper()
	dir := t.TempDir()
	fd, e := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { unix.Close(fd) })
	return dir, fd
}
func TestPlanIsNonMutating(t *testing.T) {
	var out bytes.Buffer
	code := run(context.Background(), []string{"--lan-ip", "192.168.1.50"}, &out, dependencies{})
	if code != 0 || !strings.Contains(out.String(), "plan") || !strings.Contains(out.String(), outputDirectory) {
		t.Fatal("plan failed")
	}
	for _, bad := range [][]string{{"--password", "do-not-echo-this"}, {"--lan-ip", "8.8.8.8"}, {"--lan-ip", "0.0.0.0"}, {"--lan-ip", "127.0.0.1"}, {"--lan-ip", "::1"}, {"--lan-ip", "192.168.1.50", "extra"}} {
		out.Reset()
		if run(context.Background(), bad, &out, dependencies{}) == 0 || strings.Contains(out.String(), "do-not-echo-this") {
			t.Fatal("invalid arguments accepted or echoed")
		}
	}
}
func TestApplyGatesBeforePromptOrMutation(t *testing.T) {
	for _, tc := range []struct {
		ack, root bool
		want      string
	}{{false, true, "acknowledgement"}, {true, false, "root required"}} {
		args := []string{"--lan-ip", "10.20.30.40", "--apply"}
		if tc.ack {
			args = append(args, "--ack-disposable-http-test")
		}
		var out bytes.Buffer
		if run(context.Background(), args, &out, dependencies{root: func() bool { return tc.root }}) == 0 || !strings.Contains(out.String(), tc.want) {
			t.Fatal("apply gate failed")
		}
	}
}
func TestPasswordPolicy(t *testing.T) {
	for _, good := range [][]byte{bytes.Repeat([]byte{'a'}, 12), bytes.Repeat([]byte{'b'}, 1024), []byte(strings.Repeat("界", 4))} {
		if !validPassword(good) {
			t.Fatal("valid bounded UTF-8 rejected")
		}
	}
	for _, bad := range [][]byte{nil, bytes.Repeat([]byte{'a'}, 11), bytes.Repeat([]byte{'a'}, 1025), append(bytes.Repeat([]byte{'a'}, 12), 0xff), []byte("twelve-bytes\n"), []byte("twelve-bytes\x00")} {
		if validPassword(bad) {
			t.Fatal("invalid password accepted")
		}
	}
}
func TestGeneratedMaterialPublishedSchemaAndLoaders(t *testing.T) {
	files := fixtureFiles(t)
	dir, parent := temporaryParent(t)
	if publish(context.Background(), parent, files, os.Geteuid(), os.Getegid()) != nil {
		t.Fatal("synthetic publication failed")
	}
	dest := filepath.Join(dir, outputName)
	info, e := os.Stat(dest)
	if e != nil || info.Mode().Perm() != 0700 {
		t.Fatal("directory protection failed")
	}
	entries, e := os.ReadDir(dest)
	if e != nil || len(entries) != 6 {
		t.Fatal("unexpected material count")
	}
	for _, f := range files {
		info, e := os.Lstat(filepath.Join(dest, f.name))
		if e != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatal("file protection failed")
		}
		st := info.Sys().(*syscall.Stat_t)
		if st.Uid != uint32(os.Geteuid()) || st.Gid != uint32(os.Getegid()) || st.Nlink != 1 {
			t.Fatal("owner or link protection failed")
		}
	}
	var lan lanconfig.Config
	if json.Unmarshal(files[0].data, &lan) != nil {
		t.Fatal("invalid LAN JSON")
	}
	if lan.OperatorOrigin != "http://192.168.1.50:8787" || lan.AgentOrigin != "http://192.168.1.50:8788" || lan.AgentClientCAFile != "/run/tracebolt/client-issuer.pem" || lan.StateDirectory != "/data/state" || lan.WebDirectory != "/tracebolt/web" {
		t.Fatal("container contract changed")
	}
	var enrollment enrollmentconfig.Config
	if json.Unmarshal(files[2].data, &enrollment) != nil || bytes.Contains(files[2].data, []byte("collectionProfile")) || enrollment.BootstrapServerCAFile != "" {
		t.Fatal("published schema changed")
	}
	// Only synthetic temporary copies are remapped for the existing protected loaders.
	lan.OperatorAuthFile = filepath.Join(dest, "operator-auth.json")
	lan.AgentClientCAFile = filepath.Join(dest, "client-issuer.pem")
	enrollment.IssuerCertificateFile = lan.AgentClientCAFile
	enrollment.IssuerPrivateKeyFile = filepath.Join(dest, "client-issuer.key")
	enrollment.IssuerRootFile = filepath.Join(dest, "client-root.pem")
	writeJSON := func(name string, v any) {
		raw, e := json.Marshal(v)
		if e != nil {
			t.Fatal("fixture marshal")
		}
		defer clear(raw)
		if os.WriteFile(filepath.Join(dest, name), raw, 0600) != nil {
			t.Fatal("fixture write")
		}
	}
	writeJSON("http-test.json", lan)
	writeJSON("enrollment.json", enrollment)
	loaded, e := lanconfig.Load(filepath.Join(dest, "http-test.json"))
	if e != nil {
		t.Fatal("published LAN loader rejected synthetic files")
	}
	if _, e = operatorauth.New(operatorauth.Config{PasswordHash: loaded.PasswordHash}); e != nil {
		t.Fatal("published auth loader rejected PHC")
	}
	if !strings.HasPrefix(loaded.PasswordHash, "$argon2id$v=19$m=65536,t=2,p=1$") {
		t.Fatal("PHC parameters changed")
	}
	enrolled, e := enrollmentconfig.Load(filepath.Join(dest, "enrollment.json"), loaded, fixtureTime())
	if e != nil || !enrolled.ValidFor(lan) {
		t.Fatal("published enrollment loader rejected synthetic files")
	}
	certBlock, _ := pem.Decode(files[3].data)
	rootBlock, _ := pem.Decode(files[5].data)
	if enrollmentissuer.ValidatePublicAuthority(certBlock.Bytes, rootBlock.Bytes, enrollment.ExpectedIssuerFingerprint, fixtureTime()) != nil {
		t.Fatal("public issuer policy failed")
	}
	keyBlock, _ := pem.Decode(files[4].data)
	defer clear(keyBlock.Bytes)
	key, e := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if e != nil {
		t.Fatal("private key is not PKCS8")
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		t.Fatal("wrong key type")
	}
	clear(edKey)
	cert, _ := x509.ParseCertificate(certBlock.Bytes)
	if !cert.MaxPathLenZero || cert.MaxPathLen != 0 || len(cert.ExtKeyUsage) != 1 || cert.ExtKeyUsage[0] != x509.ExtKeyUsageClientAuth {
		t.Fatal("issuer policy changed")
	}
}
func TestNoOverwriteAdoptionOrReset(t *testing.T) {
	files := fixtureFiles(t)
	for _, kind := range []string{"file", "directory", "symlink", "stale"} {
		t.Run(kind, func(t *testing.T) {
			dir, fd := temporaryParent(t)
			target := filepath.Join(dir, outputName)
			switch kind {
			case "file":
				os.WriteFile(target, []byte("preserve"), 0600)
			case "directory":
				os.Mkdir(target, 0700)
			case "symlink":
				os.Symlink("missing", target)
			case "stale":
				os.Mkdir(filepath.Join(dir, stagePrefix+"leftover"), 0700)
			}
			before, _ := os.ReadDir(dir)
			if publish(context.Background(), fd, files, os.Geteuid(), os.Getegid()) == nil {
				t.Fatal("existing output accepted")
			}
			after, _ := os.ReadDir(dir)
			if len(before) != len(after) {
				t.Fatal("existing output changed")
			}
		})
	}
}
func TestCancelledPublicationAndPasswordClearing(t *testing.T) {
	files := fixtureFiles(t)
	dir, parent := temporaryParent(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if publish(ctx, parent, files, os.Geteuid(), os.Getegid()) == nil {
		t.Fatal("cancelled publication succeeded")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 0 {
		t.Fatal("cancelled publication left staging")
	}
	password := fixturePassword()
	var out bytes.Buffer
	code := run(context.Background(), []string{"--lan-ip", "192.168.1.50", "--ack-disposable-http-test", "--apply"}, &out, dependencies{root: func() bool { return true }, openParent: func() (int, error) { return unix.Dup(parent) }, prompt: func(context.Context) ([]byte, error) { return password, errors.New("secret error must not be printed") }})
	if code == 0 || strings.Contains(out.String(), "secret error") || !bytes.Equal(password, make([]byte, len(password))) {
		t.Fatal("failure redaction or buffer clearing failed")
	}
}
func TestInjectedApplyPrintsPlanFirst(t *testing.T) {
	dir, parent := temporaryParent(t)
	var out bytes.Buffer
	password := fixturePassword()
	code := run(context.Background(), []string{"--lan-ip", "172.16.2.3", "--ack-disposable-http-test", "--apply"}, &out, dependencies{root: func() bool { return true }, openParent: func() (int, error) { return unix.Dup(parent) }, prompt: func(context.Context) ([]byte, error) {
		if !strings.Contains(out.String(), "plan") {
			t.Fatal("prompt preceded plan")
		}
		entries, _ := os.ReadDir(dir)
		if len(entries) != 0 {
			t.Fatal("file effect preceded prompt")
		}
		return password, nil
	}, random: rand.New(rand.NewSource(19)), now: fixtureTime, uid: os.Geteuid(), gid: os.Getegid()})
	if code != 0 || !strings.Contains(out.String(), "setup complete") || strings.Contains(out.String(), "$argon2id$") || !bytes.Equal(password, make([]byte, len(password))) {
		t.Fatal("synthetic apply failed or leaked")
	}
}

func TestTerminalRestoreAndNoEcho(t *testing.T) {
	for _, mode := range []string{"success", "mismatch", "cancel", "overflow"} {
		t.Run(mode, func(t *testing.T) {
			master, e := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if e != nil {
				t.Fatal(e)
			}
			defer unix.Close(master)
			if unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0) != nil {
				t.Fatal("unlock synthetic PTY")
			}
			number, e := unix.IoctlGetInt(master, unix.TIOCGPTN)
			if e != nil {
				t.Fatal(e)
			}
			path := "/dev/pts/" + strconv.Itoa(number)
			slave, e := unix.Open(path, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
			if e != nil {
				t.Fatal(e)
			}
			defer unix.Close(slave)
			original, e := unix.IoctlGetTermios(slave, unix.TCGETS)
			if e != nil {
				t.Fatal(e)
			}
			unusual := *original
			unusual.Iflag |= unix.ISTRIP | unix.IUCLC | unix.INLCR | unix.IGNCR
			if unix.IoctlSetTermios(slave, unix.TCSETS, &unusual) != nil {
				t.Fatal("configure synthetic terminal")
			}
			original = &unusual
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { p, e := readPasswordFD(ctx, slave); clear(p); done <- e }()
			var transcript bytes.Buffer
			until := func(needle string) {
				t.Helper()
				for !strings.Contains(transcript.String(), needle) {
					if ctx.Err() != nil {
						t.Fatal("synthetic terminal timed out")
					}
					poll := []unix.PollFd{{Fd: int32(master), Events: unix.POLLIN}}
					_, e := unix.Poll(poll, 100)
					if e != nil && e != unix.EINTR {
						t.Fatal(e)
					}
					var b [2048]byte
					n, e := unix.Read(master, b[:])
					if n > 0 {
						transcript.Write(b[:n])
					}
					if e != nil && e != unix.EAGAIN && e != unix.EINTR {
						t.Fatal(e)
					}
				}
			}
			until("bytes): ")
			hidden, e := unix.IoctlGetTermios(slave, unix.TCGETS)
			if e != nil || hidden.Lflag&(unix.ECHO|unix.ECHONL) != 0 {
				t.Fatal("echo enabled at prompt")
			}
			secret := []byte("SYNTHETIC-界-Password")
			defer clear(secret)
			switch mode {
			case "cancel":
				cancel()
			case "overflow":
				unix.Write(master, bytes.Repeat([]byte{'z'}, 1025))
			default:
				unix.Write(master, append(bytes.Clone(secret), '\n'))
				until("Confirm password: ")
				if mode == "mismatch" {
					unix.Write(master, []byte("different-synthetic\n"))
				} else {
					unix.Write(master, append(bytes.Clone(secret), '\n'))
				}
			}
			select {
			case e := <-done:
				if (e == nil) != (mode == "success") {
					t.Fatal("unexpected synthetic terminal outcome")
				}
			case <-time.After(6 * time.Second):
				t.Fatal("terminal did not return")
			}
			restored, e := unix.IoctlGetTermios(slave, unix.TCGETS)
			if e != nil || *restored != *original {
				t.Fatal("terminal settings not restored")
			}
			var b [2048]byte
			for {
				n, e := unix.Read(master, b[:])
				if n > 0 {
					transcript.Write(b[:n])
				}
				if e != nil || n == 0 {
					break
				}
			}
			if bytes.Contains(transcript.Bytes(), secret) || strings.Contains(transcript.String(), "different-synthetic") {
				t.Fatal("synthetic secret echoed")
			}
		})
	}
}

func TestPublicationFailurePhasesPreserveCommittedOutput(t *testing.T) {
	files := fixtureFiles(t)
	for _, phase := range []string{"before-rename", "parent-sync", "handoff", "after-handoff"} {
		t.Run(phase, func(t *testing.T) {
			dir, parent := temporaryParent(t)
			syncs, handedOff := 0, false
			ops := publicationOps{
				sync: func(fd int) error {
					syncs++
					if phase == "before-rename" && syncs == 1 || phase == "parent-sync" && syncs == 2 || phase == "after-handoff" && syncs == 3 {
						return unix.EIO
					}
					return unix.Fsync(fd)
				},
				handoff: func(fd, uid, gid int) error {
					if phase == "handoff" {
						return unix.EPERM
					}
					handedOff = true
					return unix.Fchown(fd, uid, gid)
				},
			}
			if publishWithOps(context.Background(), parent, files, os.Geteuid(), os.Getegid(), ops) == nil {
				t.Fatal("injected failure ignored")
			}
			entries, e := os.ReadDir(dir)
			if e != nil {
				t.Fatal(e)
			}
			if phase == "before-rename" {
				if len(entries) != 0 || handedOff {
					t.Fatal("uncommitted stage not cleaned safely")
				}
				return
			}
			if len(entries) != 1 || entries[0].Name() != outputName {
				t.Fatal("committed output was removed")
			}
			committed, e := os.ReadDir(filepath.Join(dir, outputName))
			if e != nil || len(committed) != 6 {
				t.Fatal("committed files removed on uncertain failure")
			}
			if (phase == "after-handoff") != handedOff {
				t.Fatal("unexpected ownership phase")
			}
		})
	}
}
