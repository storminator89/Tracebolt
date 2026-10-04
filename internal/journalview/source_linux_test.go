//go:build linux

package journalview

import (
	"context"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// All tests use pure protection facts, synthetic files and an injected runner.
// Never call newSystemProvider, openJournalctl, runJournalctl or Collect here.
func TestExactJournalArgsAndEnvironment(t *testing.T) {
	q, _ := fixtureQuery()
	q.Start = q.Start.Add(123456 * time.Microsecond)
	got, e := journalArgs(q)
	if e != nil {
		t.Fatal(e)
	}
	want := []string{"--system", "--no-pager", "--utc", "--all", "--output=json", "--output-fields=__REALTIME_TIMESTAMP,_SYSTEMD_UNIT,_PID,_UID,UNIT,PRIORITY,MESSAGE", "--since=@1791111600.123456", "--until=@1791115200.000000", "--priority=0..7", "--", "_SYSTEMD_UNIT=demo.service", "+", "_PID=1", "_UID=0", "UNIT=demo.service"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
	if !reflect.DeepEqual(commandEnv(), []string{"LC_ALL=C", "LANG=C", "TZ=UTC", "SYSTEMD_COLORS=0", "SYSTEMD_URLIFY=0", "SYSTEMD_PAGERSECURE=1"}) {
		t.Fatal(commandEnv())
	}
	for _, bad := range []string{"*.service", "x.service _UID=0", "--directory=/fixture", "x@.service"} {
		q.Unit = bad
		if _, e := journalArgs(q); e == nil {
			t.Fatal("match injection", bad)
		}
	}
}
func TestExecutableProtectionFacts(t *testing.T) {
	elf := [4]byte{0x7f, 'E', 'L', 'F'}
	regular := uint32(unix.S_IFREG | 0755)
	safe := func(uid, mode uint32, magic [4]byte, n int, readErr error, capBytes int, capErr error) bool {
		return safeExecutable(uid, mode, magic, n, readErr, capBytes, capErr)
	}
	for _, capErr := range []error{nil, unix.ENODATA, unix.EOPNOTSUPP} {
		if !safe(0, regular, elf, 4, nil, 0, capErr) {
			t.Fatal("safe fixture rejected")
		}
	}
	for _, mode := range []uint32{unix.S_IFREG | 0775, unix.S_IFREG | 0757, regular | unix.S_ISUID, regular | unix.S_ISGID, unix.S_IFREG | 0644, unix.S_IFLNK | 0755, unix.S_IFDIR | 0755} {
		if safe(0, mode, elf, 4, nil, 0, nil) {
			t.Fatalf("mode accepted %o", mode)
		}
	}
	if safe(1000, regular, elf, 4, nil, 0, nil) || safe(0, regular, [4]byte{'#', '!', '/', 'b'}, 4, nil, 0, nil) || safe(0, regular, elf, 3, nil, 0, nil) || safe(0, regular, elf, 4, unix.EIO, 0, nil) || safe(0, regular, elf, 4, nil, 1, nil) || safe(0, regular, elf, 4, nil, -1, unix.EIO) {
		t.Fatal("unsafe executable")
	}
	for _, pair := range []struct {
		uid, mode uint32
		want      bool
	}{{0, unix.S_IFDIR | 0755, true}, {1000, unix.S_IFDIR | 0755, false}, {0, unix.S_IFDIR | 0775, false}, {0, unix.S_IFREG | 0755, false}} {
		if safeDirectory(pair.uid, pair.mode) != pair.want {
			t.Fatal(pair)
		}
	}
	for _, tc := range []struct {
		size int
		err  error
		want bool
	}{{0, nil, true}, {1, nil, false}, {-1, unix.ENODATA, true}, {-1, unix.EOPNOTSUPP, true}, {0, unix.EIO, false}, {-1, nil, false}, {0, unix.EACCES, false}} {
		if noFileCapabilities(tc.size, tc.err) != tc.want {
			t.Fatal(tc)
		}
	}
	if dirFlags&unix.O_NOFOLLOW == 0 || dirFlags&unix.O_CLOEXEC == 0 || readFlags&unix.O_NOFOLLOW == 0 || readFlags&unix.O_NONBLOCK == 0 {
		t.Fatal("unsafe open flags")
	}
}
func syntheticLinuxProvider(t *testing.T, runner journalRunner) (*linuxProvider, **os.File) {
	t.Helper()
	var file *os.File
	return &linuxProvider{uid: func() int { return 1234 }, euid: func() int { return 1234 }, openTool: func() (*os.File, error) {
		var e error
		file, e = os.CreateTemp(t.TempDir(), "synthetic-executable-")
		return file, e
	}, run: runner}, &file
}
func TestInjectedAdapterNeverExecutesAndClosesDescriptor(t *testing.T) {
	q, now := fixtureQuery()
	called := false
	p, descriptor := syntheticLinuxProvider(t, func(ctx context.Context, f *os.File, args, env []string, out, errout io.Writer) error {
		called = true
		if f == nil || args[len(args)-1] != "UNIT=demo.service" || len(env) != 6 {
			t.Fatal("bad runner contract")
		}
		if _, ok := ctx.Deadline(); !ok {
			t.Fatal("no timeout")
		}
		_, e := io.WriteString(out, fixtureLine(q, "synthetic"))
		return e
	})
	s, e := CollectWithProvider(context.Background(), q, now, p)
	if e != nil || !called || s.Coverage != Complete || len(s.Rows) != 1 {
		t.Fatal(s, e)
	}
	if _, e := (*descriptor).Stat(); !errors.Is(e, os.ErrClosed) {
		t.Fatal("descriptor not closed", e)
	}
}
func TestInjectedAdapterFailureAndVisibility(t *testing.T) {
	q, now := fixtureQuery()
	for _, tc := range []struct {
		diag     string
		err      error
		reason   Reason
		coverage Coverage
	}{{"", nil, ReasonNone, Complete}, {"fixture warning", nil, ReasonVisibilityRestricted, Partial}, {"No journal files were opened due to insufficient permissions.", errors.New("exit1"), ReasonPermissionDenied, Failed}, {"fixture diagnostic", errors.New("exit1"), ReasonReadFailed, Failed}, {"", unix.EACCES, ReasonPermissionDenied, Failed}, {strings.Repeat("x", maxStderrBytes+1), errors.New("fixture cap"), ReasonByteLimit, Partial}} {
		p, _ := syntheticLinuxProvider(t, func(ctx context.Context, f *os.File, a, e []string, out, errout io.Writer) error {
			io.WriteString(errout, tc.diag)
			return tc.err
		})
		s, e := CollectWithProvider(context.Background(), q, now, p)
		if e != nil || s.Reason != tc.reason || s.Coverage != tc.coverage {
			t.Fatal(s, e, tc)
		}
	}
	p, _ := syntheticLinuxProvider(t, func(ctx context.Context, f *os.File, a, e []string, out, errout io.Writer) error {
		_, err := io.WriteString(out, strings.Repeat("x", MaxRawBytes+1))
		return err
	})
	s, e := CollectWithProvider(context.Background(), q, now, p)
	if e != nil || s.Reason != ReasonByteLimit || s.Coverage != Partial {
		t.Fatal(s, e)
	}
}
func TestRootRefusalBeforeOpenOrRunner(t *testing.T) {
	q, _ := fixtureQuery()
	for _, ids := range [][2]int{{0, 0}, {0, 1234}, {1234, 0}} {
		p := &linuxProvider{uid: func() int { return ids[0] }, euid: func() int { return ids[1] }, openTool: func() (*os.File, error) { t.Fatal("opened under root"); return nil, nil }, run: func(context.Context, *os.File, []string, []string, io.Writer, io.Writer) error {
			t.Fatal("ran under root")
			return nil
		}}
		if _, _, e := p.Open(context.Background(), q); failureReason(e) != ReasonPermissionDenied {
			t.Fatal(e)
		}
	}
}
func TestBoundedWritersAndOSFailures(t *testing.T) {
	b := &boundedBuffer{limit: 4}
	n, e := b.Write([]byte("123456"))
	if n != 4 || e != ErrSourceLimit || !b.exceeded || string(b.Bytes()) != "1234" || cap(b.data) != 4 {
		t.Fatal(b, n, e)
	}
	n, e = b.Write([]byte("7"))
	if n != 0 || e != ErrSourceLimit || b.Len() != 4 {
		t.Fatal(b, n, e)
	}
	for _, tc := range []struct {
		err  error
		want Reason
	}{{unix.EPERM, ReasonPermissionDenied}, {unix.ENOENT, ReasonSourceMissing}, {unix.ENOTDIR, ReasonSourceMissing}, {unix.ELOOP, ReasonInvalidSource}, {unix.EIO, ReasonReadFailed}} {
		if failureReason(osFailure(tc.err)) != tc.want {
			t.Fatal(tc)
		}
	}
}
