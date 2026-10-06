//go:build linux

package systeminventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// All descriptors, syscall results and proc contents below are invented. These
// tests NEVER call CaptureSocketOwners, a native factory or a host collector.
type helperWitnessFixture struct {
	st                    unix.Stat_t
	fs                    unix.Statfs_t
	sx                    unix.Statx_t
	options               map[int]int
	fail                  string
	statxErr              error
	dups, closes, queries int
}

func newHelperWitnessFixture() *helperWitnessFixture {
	return &helperWitnessFixture{
		st:      unix.Stat_t{Mode: unix.S_IFSOCK | 0600, Ino: 100, Dev: 7},
		fs:      unix.Statfs_t{Type: unix.SOCKFS_MAGIC},
		sx:      unix.Statx_t{Mask: unix.STATX_INO | unix.STATX_MNT_ID | unix.STATX_TYPE, Mode: unix.S_IFSOCK, Ino: 100, Mnt_id: 9, Dev_minor: 7},
		options: map[int]int{unix.SO_DOMAIN: unix.AF_UNIX, unix.SO_TYPE: unix.SOCK_STREAM, unix.SO_ACCEPTCONN: 1},
	}
}
func (f *helperWitnessFixture) ops(t *testing.T) socketHelperWitnessOps {
	t.Helper()
	checkFD := func(fd int) {
		t.Helper()
		if fd != 51 {
			t.Fatalf("not the pinned duplicate: %d", fd)
		}
	}
	return socketHelperWitnessOps{
		fstat: func(fd int, st *unix.Stat_t) error {
			checkFD(fd)
			f.queries++
			if f.fail == "stat" {
				return unix.EBADF
			}
			*st = f.st
			return nil
		},
		fstatfs: func(fd int, fs *unix.Statfs_t) error {
			checkFD(fd)
			f.queries++
			if f.fail == "fs" {
				return unix.EIO
			}
			*fs = f.fs
			return nil
		},
		getsockopt: func(fd, level, option int) (int, error) {
			checkFD(fd)
			f.queries++
			if level != unix.SOL_SOCKET {
				t.Fatal("wrong option level")
			}
			if f.fail == strconv.Itoa(option) {
				return 0, unix.EIO
			}
			return f.options[option], nil
		},
		statx: func(fd int, name string, flags, mask int, sx *unix.Statx_t) error {
			checkFD(fd)
			f.queries++
			if name != "" || flags != unix.AT_EMPTY_PATH|unix.AT_SYMLINK_NOFOLLOW || mask != unix.STATX_INO|unix.STATX_MNT_ID|unix.STATX_TYPE {
				t.Fatal("statx was not descriptor-bound")
			}
			*sx = f.sx
			return f.statxErr
		},
		close: func(fd int) error { checkFD(fd); f.closes++; return nil },
	}
}
func (f *helperWitnessFixture) duplicate() (int, error) {
	f.dups++
	if f.fail == "dup" {
		return -1, unix.EBADF
	}
	return 51, nil
}
func TestSocketHelperWitnessPinsExactSockfsDescriptor(t *testing.T) {
	f := newHelperWitnessFixture()
	w, err := pinSocketHelperWitness(f.duplicate, f.ops(t))
	if err != nil || w.mount != 9 || w.inode != 100 || f.closes != 0 || f.dups != 1 || f.queries != 6 {
		t.Fatalf("witness=%+v fixture=%+v err=%v", w, f, err)
	}
	if err := w.close(); err != nil || f.closes != 1 {
		t.Fatal("held witness cleanup failed")
	}
}
func TestSocketHelperWitnessRejectsInvalidOrUnsupportedProof(t *testing.T) {
	cases := []struct {
		name   string
		change func(*helperWitnessFixture)
	}{
		{"duplicate", func(f *helperWitnessFixture) { f.fail = "dup" }},
		{"fstat", func(f *helperWitnessFixture) { f.fail = "stat" }},
		{"not socket", func(f *helperWitnessFixture) { f.st.Mode = unix.S_IFREG }},
		{"zero inode", func(f *helperWitnessFixture) { f.st.Ino = 0 }},
		{"fstatfs", func(f *helperWitnessFixture) { f.fail = "fs" }},
		{"not sockfs", func(f *helperWitnessFixture) { f.fs.Type = unix.PROC_SUPER_MAGIC }},
		{"not unix", func(f *helperWitnessFixture) { f.options[unix.SO_DOMAIN] = unix.AF_INET }},
		{"not stream", func(f *helperWitnessFixture) { f.options[unix.SO_TYPE] = unix.SOCK_DGRAM }},
		{"not listening", func(f *helperWitnessFixture) { f.options[unix.SO_ACCEPTCONN] = 0 }},
		{"option error", func(f *helperWitnessFixture) { f.fail = strconv.Itoa(unix.SO_DOMAIN) }},
		{"no statx", func(f *helperWitnessFixture) { f.statxErr = unix.ENOSYS }},
		{"statx error", func(f *helperWitnessFixture) { f.statxErr = unix.EIO }},
		{"mount mask missing", func(f *helperWitnessFixture) { f.sx.Mask &^= unix.STATX_MNT_ID }},
		{"inode mask missing", func(f *helperWitnessFixture) { f.sx.Mask &^= unix.STATX_INO }},
		{"type mask missing", func(f *helperWitnessFixture) { f.sx.Mask &^= unix.STATX_TYPE }},
		{"wrong inode", func(f *helperWitnessFixture) { f.sx.Ino++ }},
		{"wrong type", func(f *helperWitnessFixture) { f.sx.Mode = unix.S_IFREG }},
		{"wrong device", func(f *helperWitnessFixture) { f.sx.Dev_major++ }},
		{"zero mount", func(f *helperWitnessFixture) { f.sx.Mnt_id = 0 }},
		{"unsupported mount range", func(f *helperWitnessFixture) { f.sx.Mnt_id = 1 << 31 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newHelperWitnessFixture()
			tc.change(f)
			w, err := pinSocketHelperWitness(f.duplicate, f.ops(t))
			if err == nil || w != nil {
				t.Fatal("accepted invalid witness")
			}
			want := 1
			if f.fail == "dup" {
				want = 0
			}
			if f.closes != want {
				t.Fatalf("closes=%d", f.closes)
			}
		})
	}
}

type helperIdentityFixture struct {
	uids, gids                  [3]int
	groups                      []int
	data                        [2]unix.CapUserData
	bound, ambient              uint64
	groupsErr, capErr, prctlErr error
	lastCap                     int
	wrongVersion                bool
}

func newHelperIdentityFixture() *helperIdentityFixture {
	const cap = 1 << unix.CAP_SYS_PTRACE
	return &helperIdentityFixture{uids: [3]int{1201, 1201, 1201}, gids: [3]int{1202, 1202, 1202}, data: [2]unix.CapUserData{{Effective: cap, Permitted: cap, Inheritable: cap}}, bound: cap, ambient: cap, lastCap: 40}
}
func (f *helperIdentityFixture) ops(t *testing.T) socketHelperIdentityOps {
	return socketHelperIdentityOps{
		uids: func() (int, int, int) { return f.uids[0], f.uids[1], f.uids[2] }, gids: func() (int, int, int) { return f.gids[0], f.gids[1], f.gids[2] }, groups: func() ([]int, error) { return f.groups, f.groupsErr },
		capget: func(h *unix.CapUserHeader, d *unix.CapUserData) error {
			if h.Version != unix.LINUX_CAPABILITY_VERSION_3 || h.Pid != 0 {
				t.Fatal("noncurrent capability query")
			}
			*(*[2]unix.CapUserData)(unsafe.Pointer(d)) = f.data
			if f.wrongVersion {
				h.Version = 0
			}
			return f.capErr
		},
		prctl: func(option int, a, b, c, d uintptr) (int, error) {
			if f.prctlErr != nil {
				return 0, f.prctlErr
			}
			if c != 0 || d != 0 {
				t.Fatal("unexpected prctl args")
			}
			cap := a
			bits := f.bound
			if option == unix.PR_CAP_AMBIENT {
				if a != unix.PR_CAP_AMBIENT_IS_SET {
					t.Fatal("mutating prctl")
				}
				cap = b
				bits = f.ambient
			} else if option != unix.PR_CAPBSET_READ || b != 0 {
				t.Fatal("mutating prctl")
			}
			if int(cap) > f.lastCap {
				return 0, unix.EINVAL
			}
			return int((bits >> cap) & 1), nil
		},
	}
}
func TestSocketHelperIdentityRequiresExactPtraceOnlyNonrootGate(t *testing.T) {
	f := newHelperIdentityFixture()
	if err := verifySocketHelperIdentity(f.ops(t)); err != nil {
		t.Fatal(err)
	}
	f.groups = []int{f.gids[0]}
	if err := verifySocketHelperIdentity(f.ops(t)); err != nil {
		t.Fatal("primary group from systemd initgroups rejected:", err)
	}
	cases := []struct {
		name   string
		change func(*helperIdentityFixture)
	}{
		{"root", func(f *helperIdentityFixture) { f.uids = [3]int{0, 0, 0} }},
		{"root group", func(f *helperIdentityFixture) { f.gids = [3]int{0, 0, 0} }},
		{"mixed uid", func(f *helperIdentityFixture) { f.uids[2]++ }},
		{"mixed gid", func(f *helperIdentityFixture) { f.gids[0]++ }},
		{"foreign supplementary group", func(f *helperIdentityFixture) { f.groups = []int{1203} }},
		{"root supplementary group", func(f *helperIdentityFixture) { f.groups = []int{0} }},
		{"duplicate primary groups", func(f *helperIdentityFixture) { f.groups = []int{1202, 1202} }},
		{"primary and foreign groups", func(f *helperIdentityFixture) { f.groups = []int{1202, 1203} }},
		{"groups error", func(f *helperIdentityFixture) { f.groupsErr = unix.EIO }},
		{"cap error", func(f *helperIdentityFixture) { f.capErr = unix.EIO }},
		{"version", func(f *helperIdentityFixture) { f.wrongVersion = true }},
		{"no effective", func(f *helperIdentityFixture) { f.data[0].Effective = 0 }},
		{"extra DAC", func(f *helperIdentityFixture) { f.data[0].Permitted |= 1 << unix.CAP_DAC_READ_SEARCH }},
		{"extra inheritable", func(f *helperIdentityFixture) { f.data[0].Inheritable |= 1 }},
		{"high capability", func(f *helperIdentityFixture) { f.data[1].Effective = 1 }},
		{"extra bounding", func(f *helperIdentityFixture) { f.bound |= 1 }},
		{"missing ambient", func(f *helperIdentityFixture) { f.ambient = 0 }},
		{"extra ambient", func(f *helperIdentityFixture) { f.ambient |= 1 }},
		{"prctl error", func(f *helperIdentityFixture) { f.prctlErr = unix.EIO }},
		{"missing ptrace support", func(f *helperIdentityFixture) { f.lastCap = 18 }},
		{"future cap ABI", func(f *helperIdentityFixture) { f.lastCap = 64 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newHelperIdentityFixture()
			tc.change(f)
			if err := verifySocketHelperIdentity(f.ops(t)); err == nil {
				t.Fatal("accepted identity")
			}
		})
	}
}

type helperProcFixture struct {
	t                        *testing.T
	dirs                     map[string][]string
	files                    map[string]string
	openErr, closeErr        map[string]error
	dirErr                   map[string]error
	handles                  map[int]string
	opened, closed           map[string]int
	readBytes, maxRead       map[string]int
	events                   []string
	next                     int
	witnessClosed, gateCalls int
	gateFailAt               int
	afterRead                func(string)
}

func newHelperProcFixture(t *testing.T) *helperProcFixture {
	f := &helperProcFixture{t: t, dirs: map[string][]string{"/proc": {}, "/proc/4242": {}, "/proc/4242/net": {}, "/proc/10": {}, "/proc/10/fdinfo": {"3"}}, files: map[string]string{}, openErr: map[string]error{}, closeErr: map[string]error{}, dirErr: map[string]error{}, handles: map[int]string{}, opened: map[string]int{}, closed: map[string]int{}, readBytes: map[string]int{}, maxRead: map[string]int{}}
	f.dirs["/proc"] = []string{"self", "net", "0", "01", "10"}
	for _, k := range []SocketSource{TCP4Source, TCP6Source, UDP4Source, UDP6Source} {
		f.files["/proc/4242/net/"+string(k)] = netHeader
	}
	f.files["/proc/4242/net/tcp"] = netHeader + procRow("00000000:0050", "00000000:0000", "0A", 123)
	f.files["/proc/10/fdinfo/3"] = socketFDInfo + "private-fixture-suffix: never read\n"
	f.files["/proc/10/comm"] = "fixture\n"
	return f
}
func (f *helperProcFixture) name(parent int, name string) string {
	f.t.Helper()
	if parent == -1 {
		if name != "/proc" {
			f.t.Fatal("unfixed root")
		}
		return name
	}
	base, ok := f.handles[parent]
	if !ok {
		f.t.Fatal("unheld parent")
	}
	return path.Join(base, name)
}
func (f *helperProcFixture) ops() socketHelperFiles {
	return socketHelperFiles{
		openDir: func(parent int, name string) (socketHelperDir, error) {
			full := f.name(parent, name)
			f.events = append(f.events, "dir "+full)
			if e := f.openErr[full]; e != nil {
				return nil, e
			}
			names, ok := f.dirs[full]
			if !ok {
				f.t.Fatalf("unapproved directory: %s", full)
			}
			f.next++
			f.handles[f.next] = full
			f.opened[full]++
			return &helperProcDirFixture{f: f, id: f.next, name: full, names: names}, nil
		},
		openFile: func(parent int, name string) (io.ReadCloser, error) {
			full := f.name(parent, name)
			f.events = append(f.events, "file "+full)
			if e := f.openErr[full]; e != nil {
				return nil, e
			}
			raw, ok := f.files[full]
			if !ok {
				f.t.Fatalf("unapproved file: %s", full)
			}
			f.opened[full]++
			return &helperProcFileFixture{f: f, name: full, Reader: strings.NewReader(raw)}, nil
		},
		readlink: func(parent int, name string, b []byte) (int, error) {
			full := f.name(parent, name)
			f.events = append(f.events, "link "+full)
			switch full {
			case "/proc/net":
				return copy(b, "self/net"), nil
			case "/proc/self":
				return copy(b, "4242"), nil
			default:
				f.t.Fatalf("forbidden link fallback: %s", full)
				return 0, unix.EINVAL
			}
		},
	}
}
func (f *helperProcFixture) deps() socketHelperDependencies {
	return socketHelperDependencies{
		gate: func() error {
			f.gateCalls++
			if f.gateCalls == f.gateFailAt {
				return SourceError{ReasonPermissionDenied}
			}
			return nil
		},
		pin: func() (*socketHelperWitness, error) {
			return &socketHelperWitness{mount: 9, inode: 100, close: func() error {
				if len(f.handles) != 0 {
					f.t.Fatal("witness closed before source handles")
				}
				f.witnessClosed++
				return f.closeErr["witness"]
			}}, nil
		}, files: f.ops(),
	}
}
func (f *helperProcFixture) checkClosed() {
	f.t.Helper()
	if len(f.handles) != 0 || f.witnessClosed != 1 || !reflect.DeepEqual(f.opened, f.closed) {
		f.t.Fatalf("leaks: opened=%v closed=%v live=%v witness=%d", f.opened, f.closed, f.handles, f.witnessClosed)
	}
}
func (f *helperProcFixture) capture(ctx context.Context, guard func() error) ([]Socket, error) {
	return captureSocketOwnersWith(ctx, testID, testAt, guard, f.deps())
}

type helperProcDirFixture struct {
	f      *helperProcFixture
	id     int
	name   string
	names  []string
	offset int
}

func (d *helperProcDirFixture) fd() int { return d.id }
func (d *helperProcDirFixture) Readdirnames(n int) ([]string, error) {
	if n < 1 || n > 128 {
		d.f.t.Fatal("unbounded dir batch")
	}
	d.f.events = append(d.f.events, "batch "+d.name)
	if e := d.f.dirErr[d.name]; e != nil {
		return nil, e
	}
	end := min(d.offset+n, len(d.names))
	out := d.names[d.offset:end]
	d.offset = end
	if end == len(d.names) {
		return out, io.EOF
	}
	return out, nil
}
func (d *helperProcDirFixture) Close() error {
	d.f.closed[d.name]++
	delete(d.f.handles, d.id)
	return d.f.closeErr[d.name]
}

type helperProcFileFixture struct {
	*strings.Reader
	f    *helperProcFixture
	name string
}

func (r *helperProcFileFixture) Read(b []byte) (int, error) {
	r.f.maxRead[r.name] = max(r.f.maxRead[r.name], len(b))
	n, e := r.Reader.Read(b)
	r.f.readBytes[r.name] += n
	if r.f.afterRead != nil {
		r.f.afterRead(r.name)
	}
	return n, e
}
func (r *helperProcFileFixture) Close() error { r.f.closed[r.name]++; return r.f.closeErr[r.name] }

func TestSocketHelperCaptureFixedTablesAndPrefixOnlyOwners(t *testing.T) {
	f := newHelperProcFixture(t)
	rows, err := f.capture(context.Background(), func() error { return nil })
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	if rows[0].Attribution != (Attribution{AttributionObserved, ReasonNone}) || len(rows[0].Owners) != 1 || rows[0].Owners[0].PID != 10 || *rows[0].Owners[0].ProcessName != "fixture" {
		t.Fatalf("row=%+v", rows[0])
	}
	if f.readBytes["/proc/10/fdinfo/3"] != len(socketFDInfo) || f.maxRead["/proc/10/fdinfo/3"] != 1 {
		t.Fatal("read descriptor-specific suffix or ahead")
	}
	for _, k := range []SocketSource{TCP4Source, TCP6Source, UDP4Source, UDP6Source} {
		if f.opened["/proc/4242/net/"+string(k)] != 1 {
			t.Fatal("missing source")
		}
	}
	b, _ := json.Marshal(rows)
	for _, secret := range []string{"private-fixture", "inode", "mnt_id", "fdinfo"} {
		if strings.Contains(string(b), secret) {
			t.Fatal("raw metadata escaped")
		}
	}
	f.checkClosed()
}
func TestSocketHelperCaptureExactMountAndInodeNoLinkFallback(t *testing.T) {
	for _, raw := range []string{strings.Replace(socketFDInfo, "mnt_id:\t9", "mnt_id:\t10", 1), strings.Replace(socketFDInfo, "ino:\t123", "ino:\t456", 1), strings.Replace(socketFDInfo, "ino:\t123", "ino:\t0", 1)} {
		f := newHelperProcFixture(t)
		f.files["/proc/10/fdinfo/3"] = raw
		rows, err := f.capture(context.Background(), func() error { return nil })
		if err != nil || len(rows) != 1 || rows[0].Attribution != (Attribution{AttributionUnavailable, ReasonNoMatch}) || len(rows[0].Owners) != 0 || f.opened["/proc/10/comm"] != 0 {
			t.Fatalf("bad matching: rows=%v err=%v", rows, err)
		}
		f.checkClosed()
	}
}
func TestSocketHelperCaptureUnknownsPreserveObservedOwners(t *testing.T) {
	cases := []struct {
		name   string
		change func(*helperProcFixture)
		reason Reason
		owners int
	}{
		{"missing ino", func(f *helperProcFixture) { f.files["/proc/10/fdinfo/3"] = "pos:\t0\nflags:\t02\nmnt_id:\t9\n" }, ReasonNotSupported, 0},
		{"malformed header", func(f *helperProcFixture) { f.files["/proc/10/fdinfo/3"] = "ino:\t123\n" }, ReasonInvalidSource, 0},
		{"denied fdinfo", func(f *helperProcFixture) { f.openErr["/proc/10/fdinfo/3"] = SourceError{ReasonPermissionDenied} }, ReasonPermissionDenied, 0},
		{"gone process", func(f *helperProcFixture) { f.openErr["/proc/10"] = SourceError{ReasonSourceMissing} }, ReasonProcessGone, 0},
		{"denied comm", func(f *helperProcFixture) { f.openErr["/proc/10/comm"] = SourceError{ReasonPermissionDenied} }, ReasonPermissionDenied, 1},
		{"bad comm", func(f *helperProcFixture) { f.files["/proc/10/comm"] = "invalid/name\n" }, ReasonInvalidSource, 1},
		{"directory read error", func(f *helperProcFixture) { f.dirErr["/proc/10/fdinfo"] = io.ErrUnexpectedEOF }, ReasonReadFailed, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newHelperProcFixture(t)
			tc.change(f)
			rows, err := f.capture(context.Background(), func() error { return nil })
			if err != nil || len(rows) != 1 || rows[0].Attribution != (Attribution{AttributionPartial, tc.reason}) || len(rows[0].Owners) != tc.owners {
				t.Fatalf("rows=%+v err=%v", rows, err)
			}
			f.checkClosed()
		})
	}
}
func TestSocketHelperCaptureZeroRowsAndTableFailureDiffer(t *testing.T) {
	f := newHelperProcFixture(t)
	f.files["/proc/4242/net/tcp"] = netHeader
	rows, err := f.capture(context.Background(), func() error { return nil })
	if err != nil || rows == nil || len(rows) != 0 || f.opened["/proc/10"] != 0 {
		t.Fatal("zero-row observation failed")
	}
	f.checkClosed()
	for _, raw := range []string{"", netHeader + "bad\n", netHeader + strings.Repeat(procRow("00000000:0050", "00000000:0000", "0A", 123), MaxSocketRows+1)} {
		f := newHelperProcFixture(t)
		f.files["/proc/4242/net/tcp"] = raw
		rows, err := f.capture(context.Background(), func() error { return nil })
		if err == nil || rows != nil || f.opened["/proc/10"] != 0 {
			t.Fatal("failed source was complete")
		}
		f.checkClosed()
	}
}
func TestSocketHelperCaptureCloseFailureDiscardsRows(t *testing.T) {
	for _, name := range []string{"/proc", "/proc/4242", "/proc/4242/net", "/proc/4242/net/tcp", "/proc/10", "/proc/10/fdinfo", "/proc/10/fdinfo/3", "/proc/10/comm", "witness"} {
		t.Run(name, func(t *testing.T) {
			f := newHelperProcFixture(t)
			f.closeErr[name] = io.ErrUnexpectedEOF
			rows, err := f.capture(context.Background(), func() error { return nil })
			if err == nil || rows != nil {
				t.Fatal("cleanup failure retained rows")
			}
			f.checkClosed()
		})
	}
}
func TestSocketHelperCaptureRevocationStickyAtEveryGuardAndCleanup(t *testing.T) {
	f := newHelperProcFixture(t)
	checks := 0
	if _, err := f.capture(context.Background(), func() error { checks++; return nil }); err != nil {
		t.Fatal(err)
	}
	f.checkClosed()
	for failAt := 1; failAt <= checks; failAt++ {
		t.Run(strconv.Itoa(failAt), func(t *testing.T) {
			f := newHelperProcFixture(t)
			calls := 0
			rows, err := f.capture(context.Background(), func() error {
				calls++
				if calls == failAt {
					return errors.New("private policy details")
				}
				return nil
			})
			if err == nil || rows != nil || strings.Contains(err.Error(), "private") {
				t.Fatal("revoked capture survived or leaked detail")
			}
			if failAt == 1 {
				if len(f.events) != 0 || f.witnessClosed != 0 {
					t.Fatal("source opened before admission")
				}
			} else {
				f.checkClosed()
			}
		})
	}
}
func TestSocketHelperCaptureCancellationInsideFDHeaderCleansSynchronously(t *testing.T) {
	f := newHelperProcFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	f.afterRead = func(name string) {
		if name == "/proc/10/fdinfo/3" {
			cancel()
		}
	}
	rows, err := f.capture(ctx, func() error { return nil })
	if rows != nil || !errors.Is(err, context.Canceled) || f.readBytes["/proc/10/fdinfo/3"] != 1 || f.opened["/proc/10/comm"] != 0 {
		t.Fatalf("rows=%v err=%v reads=%d", rows, err, f.readBytes["/proc/10/fdinfo/3"])
	}
	f.checkClosed()
}
func TestSocketHelperCaptureIdentityFailureBeforeAndAfterSource(t *testing.T) {
	for _, at := range []int{1, 2} {
		f := newHelperProcFixture(t)
		f.gateFailAt = at
		rows, err := f.capture(context.Background(), func() error { return nil })
		if err == nil || rows != nil {
			t.Fatal("identity gate bypass")
		}
		if at == 1 {
			if len(f.events) != 0 || f.witnessClosed != 0 {
				t.Fatal("read source before identity")
			}
		} else {
			f.checkClosed()
		}
	}
}
func TestSocketHelperCaptureFDWorkLimitRetainsPartialOwner(t *testing.T) {
	f := newHelperProcFixture(t)
	names := make([]string, MaxFDEntriesPerProcess+1)
	for i := range names {
		name := strconv.Itoa(i)
		names[i] = name
		f.files["/proc/10/fdinfo/"+name] = socketFDInfo
	}
	f.dirs["/proc/10/fdinfo"] = names
	rows, err := f.capture(context.Background(), func() error { return nil })
	if err != nil || len(rows) != 1 || len(rows[0].Owners) != 1 || rows[0].Attribution != (Attribution{AttributionPartial, ReasonWorkLimit}) {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	if f.opened["/proc/10/fdinfo/"+strconv.Itoa(MaxFDEntriesPerProcess)] != 0 {
		t.Fatal("opened beyond fd limit")
	}
	f.checkClosed()
}
func TestSocketHelperCaptureDirectoryWorkLimitIsExplicit(t *testing.T) {
	f := newHelperProcFixture(t)
	f.dirs["/proc"] = make([]string, MaxDirectoryEntries+1)
	for i := range f.dirs["/proc"] {
		f.dirs["/proc"][i] = "nonnumeric"
	}
	rows, err := f.capture(context.Background(), func() error { return nil })
	if err != nil || len(rows) != 1 || rows[0].Attribution != (Attribution{AttributionPartial, ReasonWorkLimit}) {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	f.checkClosed()
}
func TestSocketHelperCaptureSharedDuplicateFDsAndOwnerLimit(t *testing.T) {
	f := newHelperProcFixture(t)
	f.dirs["/proc"] = nil
	for pid := 1; pid <= MaxOwnersPerSocket+1; pid++ {
		name := fmt.Sprintf("/proc/%d", pid)
		f.dirs["/proc"] = append(f.dirs["/proc"], strconv.Itoa(pid))
		f.dirs[name] = nil
		f.dirs[name+"/fdinfo"] = []string{"3", "4"}
		f.files[name+"/fdinfo/3"] = socketFDInfo
		f.files[name+"/fdinfo/4"] = socketFDInfo
		f.files[name+"/comm"] = "fixture\n"
	}
	rows, err := f.capture(context.Background(), func() error { return nil })
	if err != nil || len(rows) != 1 || len(rows[0].Owners) != MaxOwnersPerSocket || rows[0].Attribution != (Attribution{AttributionPartial, ReasonOwnerLimit}) {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	f.checkClosed()
}

func TestSocketHelperCaptureInputAndWitnessFailuresNeverReadProc(t *testing.T) {
	for _, kind := range []string{"nil context", "canceled", "nil guard", "id", "time", "witness error", "bad mount", "bad inode"} {
		t.Run(kind, func(t *testing.T) {
			f := newHelperProcFixture(t)
			ctx := context.Background()
			guard := func() error { return nil }
			id, at, deps := testID, testAt, f.deps()
			switch kind {
			case "nil context":
				ctx = nil
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "nil guard":
				guard = nil
			case "id":
				id = "../123"
			case "time":
				at = at.AddDate(-100, 0, 0)
			case "witness error":
				deps.pin = func() (*socketHelperWitness, error) { return nil, ErrInvalidSource }
			case "bad mount", "bad inode":
				pin := deps.pin
				deps.pin = func() (*socketHelperWitness, error) {
					w, e := pin()
					if kind == "bad mount" {
						w.mount = 0
					} else {
						w.inode = 0
					}
					return w, e
				}
			}
			rows, err := captureSocketOwnersWith(ctx, id, at, guard, deps)
			if err == nil || rows != nil || len(f.events) != 0 {
				t.Fatalf("invalid input opened proc: rows=%v err=%v events=%v", rows, err, f.events)
			}
			if (kind == "bad mount" || kind == "bad inode") && f.witnessClosed != 1 {
				t.Fatal("bad witness not closed")
			}
		})
	}
}

func TestSocketHelperCapturePinnedProcInitializationFailuresCloseHandles(t *testing.T) {
	for _, name := range []string{"/proc", "/proc/4242", "/proc/4242/net", "/proc/4242/net/tcp", "/proc/4242/net/tcp6", "/proc/4242/net/udp", "/proc/4242/net/udp6"} {
		t.Run(name, func(t *testing.T) {
			f := newHelperProcFixture(t)
			f.openErr[name] = SourceError{ReasonPermissionDenied}
			rows, err := f.capture(context.Background(), func() error { return nil })
			if err == nil || rows != nil {
				t.Fatal("source failure retained rows")
			}
			f.checkClosed()
		})
	}
	for _, target := range []string{"net", "self"} {
		t.Run("link "+target, func(t *testing.T) {
			f := newHelperProcFixture(t)
			deps := f.deps()
			original := deps.files.readlink
			deps.files.readlink = func(parent int, name string, b []byte) (int, error) {
				if name == target {
					return copy(b, "../private"), nil
				}
				return original(parent, name, b)
			}
			rows, err := captureSocketOwnersWith(context.Background(), testID, testAt, func() error { return nil }, deps)
			if err == nil || rows != nil {
				t.Fatal("unsafe proc self path followed")
			}
			f.checkClosed()
		})
	}
}

func TestSocketHelperCaptureAllFourFamiliesAndZeroInodeRemainDistinct(t *testing.T) {
	f := newHelperProcFixture(t)
	for _, tc := range []struct {
		kind                 SocketSource
		local, remote, state string
		inode                uint64
	}{
		{TCP4Source, "00000000:0050", "00000000:0000", "0A", 123},
		{TCP6Source, "00000000000000000000000000000000:0050", "00000000000000000000000000000000:0000", "0A", 456},
		{UDP4Source, "00000000:0050", "00000000:0000", "07", 789},
		{UDP6Source, "00000000000000000000000000000000:0050", "00000000000000000000000000000000:0000", "07", 0},
	} {
		f.files["/proc/4242/net/"+string(tc.kind)] = netHeader + procRow(tc.local, tc.remote, tc.state, tc.inode)
	}
	f.dirs["/proc/10/fdinfo"] = []string{"0", "1", "2"}
	for i, inode := range []int{123, 456, 789} {
		f.files[fmt.Sprintf("/proc/10/fdinfo/%d", i)] = strings.Replace(socketFDInfo, "ino:\t123", fmt.Sprintf("ino:\t%d", inode), 1)
	}
	rows, err := f.capture(context.Background(), func() error { return nil })
	if err != nil || len(rows) != 4 {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	for i, row := range rows {
		if i == 3 {
			if row.Attribution != (Attribution{AttributionUnavailable, ReasonNoMatch}) || len(row.Owners) != 0 {
				t.Fatal("invented zero-inode owner")
			}
		} else if len(row.Owners) != 1 || row.Owners[0].PID != 10 {
			t.Fatalf("missing owner: %+v", row)
		}
	}
	f.checkClosed()
}

func TestSocketHelperCapturePIDWorkLimitIsExplicit(t *testing.T) {
	f := newHelperProcFixture(t)
	f.dirs["/proc"] = make([]string, MaxProcessEntries+1)
	for i := range f.dirs["/proc"] {
		name := strconv.Itoa(i + 1)
		f.dirs["/proc"][i] = name
		f.openErr["/proc/"+name] = SourceError{ReasonSourceMissing}
	}
	// Do not fail the fixed own-view network directory while initializing it.
	delete(f.openErr, "/proc/4242")
	f.dirs["/proc/4242/fdinfo"] = nil
	rows, err := f.capture(context.Background(), func() error { return nil })
	if err != nil || len(rows) != 1 || rows[0].Attribution != (Attribution{AttributionPartial, ReasonWorkLimit}) {
		t.Fatalf("rows=%v err=%v", rows, err)
	}
	last := "dir /proc/" + strconv.Itoa(MaxProcessEntries+1)
	for _, event := range f.events {
		if event == last {
			t.Fatal("opened PID past work bound")
		}
	}
	f.checkClosed()
}
