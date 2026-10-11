package windowssecuritycoverage

import (
	"bytes"
	"encoding/binary"
	"go/ast"
	"go/format"
	"go/parser"
	"go/token"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func integrityFixture(width int, rid uint32) ([]byte, uint64) {
	const base = uint64(0x10000)
	b := make([]byte, 2*width+12)
	setIntegrityPointer(b, width, base+uint64(2*width))
	binary.LittleEndian.PutUint32(b[width:], 0x20)
	sid := b[2*width:]
	sid[0], sid[1], sid[7] = 1, 1, 16
	binary.LittleEndian.PutUint32(sid[8:], rid)
	return b, base
}

func setIntegrityPointer(b []byte, width int, address uint64) {
	if width == 4 {
		binary.LittleEndian.PutUint32(b, uint32(address))
	} else {
		binary.LittleEndian.PutUint64(b, address)
	}
}

// Entirely synthetic buffers exercise both Windows ABIs on every test host.
func TestActivationIntegrityAcceptsOnlyHighAndSystem(t *testing.T) {
	for _, width := range []int{4, 8} {
		for _, rid := range []uint32{0, 0x1000, 0x2000, 0x2010, 0x2100, 0x2fff, 0x3000, 0x3001, 0x4000, 0x5000, 0xffffffff} {
			b, base := integrityFixture(width, rid)
			want := rid == 0x3000 || rid == 0x4000
			if got := trustedActivationIntegrity(b, base, width); got != want {
				t.Fatalf("width=%d rid=%x: got %v, want %v", width, rid, got, want)
			}
		}
	}
}

func TestActivationIntegrityRejectsMalformedNativeRecords(t *testing.T) {
	for _, width := range []int{4, 8} {
		t.Run(strconv.Itoa(width), func(t *testing.T) {
			valid, base := integrityFixture(width, 0x4000)
			for length := 0; length < len(valid); length++ {
				if trustedActivationIntegrity(valid[:length], base, width) {
					t.Fatalf("accepted truncated record: %d", length)
				}
			}
			for name, mutate := range map[string]func([]byte){
				"null_pointer":        func(b []byte) { setIntegrityPointer(b, width, 0) },
				"pointer_before":      func(b []byte) { setIntegrityPointer(b, width, base-4) },
				"pointer_header":      func(b []byte) { setIntegrityPointer(b, width, base) },
				"pointer_past":        func(b []byte) { setIntegrityPointer(b, width, base+uint64(len(b))) },
				"pointer_overflow":    func(b []byte) { setIntegrityPointer(b, width, ^uint64(3)) },
				"pointer_unaligned":   func(b []byte) { setIntegrityPointer(b, width, base+uint64(2*width)+1) },
				"missing_integrity":   func(b []byte) { binary.LittleEndian.PutUint32(b[width:], 0x40) },
				"deny_only":           func(b []byte) { binary.LittleEndian.PutUint32(b[width:], 0x30) },
				"sid_revision":        func(b []byte) { b[2*width] = 2 },
				"sid_no_subauthority": func(b []byte) { b[2*width+1] = 0 },
				"sid_extra_rid":       func(b []byte) { b[2*width+1] = 2 },
				"sid_authority":       func(b []byte) { b[2*width+7] = 5 },
				"sid_authority_high":  func(b []byte) { b[2*width+2] = 1 },
			} {
				t.Run(name, func(t *testing.T) {
					b := bytes.Clone(valid)
					mutate(b)
					if trustedActivationIntegrity(b, base, width) {
						t.Fatal("accepted malformed label")
					}
				})
			}
			if trustedActivationIntegrity(valid, 0, width) || trustedActivationIntegrity(valid, ^uint64(0)-3, width) {
				t.Fatal("accepted invalid/overflowing base")
			}
			if trustedActivationIntegrity(append(bytes.Clone(valid), make([]byte, maxActivationTokenBytes)...), base, width) {
				t.Fatal("accepted oversized query")
			}
		})
	}
	b, base := integrityFixture(8, 0x3000)
	for _, width := range []int{-1, 0, 1, 2, 16} {
		if trustedActivationIntegrity(b, base, width) {
			t.Fatal("accepted unsupported pointer width")
		}
	}
}

func FuzzActivationIntegrityBuffer(f *testing.F) {
	for _, width := range []int{4, 8} {
		b, _ := integrityFixture(width, 0x4000)
		f.Add(b)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		for _, width := range []int{4, 8} {
			_ = trustedActivationIntegrity(b, 0x10000, width)
		}
	})
}

type activationTokenFixture struct {
	t                          *testing.T
	thread, process            uintptr
	threadErr, processErr      error
	size, returned             uint32
	sizeErr, fillErr, closeErr error
	record                     []byte
	base                       uint64
	calls                      []string
}

func (f *activationTokenFixture) api() activationTrustAPI {
	return activationTrustAPI{
		openThread: func() (uintptr, error) {
			f.calls = append(f.calls, "thread")
			return f.thread, f.threadErr
		},
		openProcess: func() (uintptr, error) {
			f.calls = append(f.calls, "process")
			return f.process, f.processErr
		},
		query: func(handle uintptr, b []byte) (uint32, error) {
			if handle != f.process {
				f.t.Fatal("queried wrong token")
			}
			if b == nil {
				f.calls = append(f.calls, "size")
				return f.size, f.sizeErr
			}
			f.calls = append(f.calls, "fill")
			if len(b) != int(f.size) || len(b) > maxActivationTokenBytes {
				f.t.Fatal("query allocation escaped declared bound")
			}
			copy(b, f.record)
			return f.returned, f.fillErr
		},
		close: func(handle uintptr) error {
			f.calls = append(f.calls, "close:"+strconv.FormatUint(uint64(handle), 10))
			return f.closeErr
		},
		bufferBase: func([]byte) uint64 {
			f.calls = append(f.calls, "parse")
			return f.base
		},
	}
}

func TestActivationTokenFailuresCloseHandlesAndStop(t *testing.T) {
	for _, width := range []int{4, 8} {
		for _, tc := range []struct {
			name   string
			change func(*activationTokenFixture)
			calls  string
			allow  bool
		}{
			{"system", func(*activationTokenFixture) {}, "thread process size fill parse close:22", true},
			{"thread_present", func(f *activationTokenFixture) { f.thread, f.threadErr = 11, nil }, "thread close:11", false},
			{"thread_close_error", func(f *activationTokenFixture) { f.thread, f.threadErr, f.closeErr = 11, nil, ErrUnavailable }, "thread close:11", false},
			{"thread_query_denied", func(f *activationTokenFixture) { f.threadErr = ErrDenied }, "thread", false},
			{"thread_query_failure", func(f *activationTokenFixture) { f.threadErr = ErrUnavailable }, "thread", false},
			{"thread_success_null", func(f *activationTokenFixture) { f.threadErr = nil }, "thread", false},
			{"process_open_denied", func(f *activationTokenFixture) { f.process, f.processErr = 0, ErrDenied }, "thread process", false},
			{"process_open_failure", func(f *activationTokenFixture) { f.process, f.processErr = 0, ErrUnavailable }, "thread process", false},
			{"process_success_null", func(f *activationTokenFixture) { f.process = 0 }, "thread process", false},
			{"size_query_failure", func(f *activationTokenFixture) { f.sizeErr = ErrUnavailable }, "thread process size close:22", false},
			{"size_unexpected_success", func(f *activationTokenFixture) { f.sizeErr = nil }, "thread process size close:22", false},
			{"size_zero", func(f *activationTokenFixture) { f.size = 0 }, "thread process size close:22", false},
			{"size_short", func(f *activationTokenFixture) { f.size-- }, "thread process size close:22", false},
			{"size_over_budget", func(f *activationTokenFixture) { f.size = maxActivationTokenBytes + 1 }, "thread process size close:22", false},
			{"fill_failure", func(f *activationTokenFixture) { f.fillErr = ErrUnavailable }, "thread process size fill close:22", false},
			{"fill_requests_retry", func(f *activationTokenFixture) { f.fillErr = errActivationBufferSize }, "thread process size fill close:22", false},
			{"fill_grows", func(f *activationTokenFixture) { f.returned++ }, "thread process size fill close:22", false},
			{"fill_zero", func(f *activationTokenFixture) { f.returned = 0 }, "thread process size fill parse close:22", false},
			{"fill_truncated", func(f *activationTokenFixture) { f.returned-- }, "thread process size fill parse close:22", false},
			{"wrong_integrity", func(f *activationTokenFixture) { binary.LittleEndian.PutUint32(f.record[len(f.record)-4:], 0x2000) }, "thread process size fill parse close:22", false},
			{"process_close_failure", func(f *activationTokenFixture) { f.closeErr = ErrUnavailable }, "thread process size fill parse close:22", false},
		} {
			t.Run(strconv.Itoa(width)+"/"+tc.name, func(t *testing.T) {
				record, base := integrityFixture(width, 0x4000)
				f := &activationTokenFixture{t: t, threadErr: errActivationNoThreadToken, process: 22, size: uint32(len(record)), returned: uint32(len(record)), sizeErr: errActivationBufferSize, record: record, base: base}
				tc.change(f)
				err := verifyActivationTrust(f.api(), width)
				if (err == nil) != tc.allow || (err != nil && err != ErrDenied) {
					t.Fatalf("trust result %v, allow=%v", err, tc.allow)
				}
				if !reflect.DeepEqual(f.calls, strings.Fields(tc.calls)) {
					t.Fatalf("calls %v, want %s", f.calls, tc.calls)
				}
			})
		}
	}
	if verifyActivationTrust(activationTrustAPI{}, 8) != ErrDenied {
		t.Fatal("missing API must fail closed")
	}
}

func activationSource(t *testing.T, path string) (*ast.File, string) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := format.Node(&b, token.NewFileSet(), f); err != nil {
		t.Fatal(err)
	}
	return f, b.String()
}

// These source-order fixtures never call Windows, initialize COM, or read a
// token. They pin the rejection/cleanup paths around the native-only boundary.
func TestActivationTrustPrecedesCOMOnLockedThread(t *testing.T) {
	f, source := activationSource(t, "automation_windows.go")
	sequence := "runtime.LockOSThread()\n\tif e := verifyNativeActivationTrust(); e != nil {\n\t\truntime.UnlockOSThread()\n\t\treturn nil, noop, e\n\t}\n\thr, _, _ := coInitializeEx.Call(0, 2)"
	if !strings.Contains(source, sequence) {
		t.Fatal("trust gate must reject and unlock before COM initialization")
	}
	var guard, initialize, activate token.Pos
	var calls int
	ast.Inspect(f, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if ident, ok := c.Fun.(*ast.Ident); ok && ident.Name == "verifyNativeActivationTrust" {
			guard = c.Pos()
		}
		if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Call" {
			if ident, ok := sel.X.(*ast.Ident); ok {
				switch ident.Name {
				case "coInitializeEx":
					initialize = c.Pos()
				case "coCreateInstance":
					activate = c.Pos()
					calls++
					if len(c.Args) != 5 {
						t.Fatal("unexpected COM activation signature")
					}
					context, ok := c.Args[2].(*ast.BasicLit)
					if !ok || context.Value != "1" {
						t.Fatal("activation must retain CLSCTX_INPROC_SERVER only")
					}
				}
			}
		}
		return true
	})
	if calls != 1 || !(guard > 0 && guard < initialize && initialize < activate) {
		t.Fatal("COM activation escaped trust gate ordering")
	}
	if !strings.Contains(source, "if e := hrError(hr); e != nil {\n\t\truntime.UnlockOSThread()\n\t\treturn nil, noop, e\n\t}") || !strings.Contains(strings.ReplaceAll(strings.Join(strings.Fields(source), ""), ";", ""), "coUninitialize.Call()runtime.UnlockOSThread()") {
		t.Fatal("COM failure/close must balance OS-thread ownership")
	}
}

func TestActivationTrustNativeSurfaceIsReadOnlyAndFailClosed(t *testing.T) {
	f, source := activationSource(t, "activation_trust_windows.go")
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || (p != "unsafe" && p != "golang.org/x/sys/windows") {
			t.Fatal("unreviewed native trust import")
		}
	}
	allowed := map[string]bool{"windows.OpenThreadToken": true, "windows.CurrentThread": true, "windows.OpenProcessToken": true, "windows.CurrentProcess": true, "windows.GetTokenInformation": true, "windows.Token": true, "windows.Token(token).Close": true, "unsafe.Sizeof": true, "unsafe.Pointer": true}
	ast.Inspect(f, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
			var b bytes.Buffer
			if format.Node(&b, token.NewFileSet(), sel) != nil || !allowed[b.String()] {
				t.Fatal("unreviewed native trust API")
			}
		}
		return true
	})
	for _, required := range []string{
		"windows.OpenThreadToken(windows.CurrentThread(), windows.TOKEN_QUERY, true, &token)",
		"if err == windows.ERROR_NO_TOKEN {\n\t\t\t\terr = errActivationNoThreadToken\n\t\t\t}",
		"windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)",
		"windows.GetTokenInformation(windows.Token(token), windows.TokenIntegrityLevel, ptr, uint32(len(b)), &needed)",
		"if err == windows.ERROR_INSUFFICIENT_BUFFER {\n\t\t\t\terr = errActivationBufferSize\n\t\t\t}",
	} {
		if !strings.Contains(strings.Join(strings.Fields(source), ""), strings.Join(strings.Fields(required), "")) {
			t.Fatal("missing read-only rejection/cleanup boundary:", required)
		}
	}
	_, coordinator := activationSource(t, "activation_trust.go")
	if strings.Count(coordinator, "api.query(process,") != 2 || strings.Contains(coordinator, "for ") {
		t.Fatal("trust coordinator must use exactly two queries without retries")
	}
}
