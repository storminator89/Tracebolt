//go:build windows

package windowsmanaged

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// These fixtures never use serviceStartupSystemAPI or a native syscall.
func startupFakeAPI(t *testing.T, startType uint32) serviceStartupNativeAPI {
	t.Helper()
	return serviceStartupNativeAPI{
		openSCM: func(machine, database *uint16, access uint32) (windows.Handle, error) {
			if machine != nil || database != nil || access != windows.SC_MANAGER_CONNECT {
				t.Fatal("not local CONNECT-only SCM")
			}
			return 1, nil
		},
		openService: func(manager windows.Handle, name *uint16, access uint32) (windows.Handle, error) {
			if manager != 1 || name == nil || access != windows.SERVICE_QUERY_CONFIG {
				t.Fatal("wrong service access")
			}
			return 2, nil
		},
		queryConfig: func(h windows.Handle, c *windows.QUERY_SERVICE_CONFIG, n uint32, needed *uint32) error {
			if h != 2 || c == nil || n != ServiceStartupMaxConfigBytes {
				t.Fatal("wrong config bound")
			}
			c.ServiceType = windows.SERVICE_WIN32_OWN_PROCESS
			c.StartType = startType
			*needed = 0
			return nil
		},
		queryConfig2: func(h windows.Handle, level uint32, b *byte, n uint32, needed *uint32) error {
			if h != 2 || level != windows.SERVICE_CONFIG_DELAYED_AUTO_START_INFO || b == nil || n != 4 {
				t.Fatal("wrong config2 level or bound")
			}
			*(*uint32)(unsafe.Pointer(b)) = 1
			*needed = 0
			return nil
		},
		close: func(h windows.Handle) error {
			if h != 1 && h != 2 {
				t.Fatal("unknown handle")
			}
			return nil
		},
	}
}

func startupCollectNativeFixture(t *testing.T, services []Service, api serviceStartupNativeAPI) (ServiceStartupSnapshot, error) {
	t.Helper()
	return collectServiceStartupUsing(context.Background(), services, startupTestGeneration, startupTestGrant, startupTestAt, func(ctx context.Context) (ServiceStartupReader, func(), error) {
		return serviceStartupNativeReaderUsing(ctx, api)
	}, serviceStartupCollectionBudget, func() time.Time { return startupTestAt.Add(time.Second) })
}

func TestServiceStartupNativeRightsAndHandleLifetime(t *testing.T) {
	api := startupFakeAPI(t, windows.SERVICE_AUTO_START)
	open, closed, managers, delayedCalls := 0, 0, 0, 0
	baseOpen := api.openService
	api.openService = func(manager windows.Handle, name *uint16, access uint32) (windows.Handle, error) {
		if open != closed {
			t.Fatal("previous service still owned before next open")
		}
		open++
		if got := windows.UTF16PtrToString(name); got != startupTestServices()[open-1].Name {
			t.Fatal("re-enumerated or substituted service")
		}
		return baseOpen(manager, name, access)
	}
	api.close = func(h windows.Handle) error {
		switch h {
		case 1:
			if open != closed {
				t.Fatal("SCM closed with service handle live")
			}
			managers++
		case 2:
			closed++
		default:
			t.Fatal(h)
		}
		return nil
	}
	baseQuery2 := api.queryConfig2
	api.queryConfig2 = func(h windows.Handle, level uint32, b *byte, n uint32, needed *uint32) error {
		delayedCalls++
		return baseQuery2(h, level, b, n, needed)
	}
	s, err := startupCollectNativeFixture(t, startupTestServices(), api)
	if err != nil || open != 2 || closed != 2 || managers != 1 || delayedCalls != 2 || len(s.Rows) != 2 || *s.Rows[0].StartupMode != "automatic" || !*s.Rows[0].DelayedAutoStart {
		t.Fatal(s, err, open, closed, managers, delayedCalls)
	}
}

func TestServiceStartupNativeBufferClearedAndNoPointersFollowed(t *testing.T) {
	api := startupFakeAPI(t, windows.SERVICE_AUTO_START)
	var aggregate []byte
	api.queryConfig = func(h windows.Handle, c *windows.QUERY_SERVICE_CONFIG, n uint32, needed *uint32) error {
		if h != 2 || n != ServiceStartupMaxConfigBytes {
			t.Fatal("wrong config call")
		}
		aggregate = unsafe.Slice((*byte)(unsafe.Pointer(c)), int(n))
		// Invalid opaque pointer bit patterns would fail if dereferenced. Only
		// the two scalar DWORDs below may ever be read from this aggregate.
		for i := range aggregate {
			aggregate[i] = 0xa5
		}
		copy(aggregate[256:], []byte(`C:\private\service.exe account=PRIVATE password=DO_NOT_EXPORT`))
		c.ServiceType = windows.SERVICE_WIN32_OWN_PROCESS
		c.StartType = windows.SERVICE_AUTO_START
		*needed = uint32(unsafe.Sizeof(*c))
		return nil
	}
	base2 := api.queryConfig2
	api.queryConfig2 = func(h windows.Handle, level uint32, b *byte, n uint32, needed *uint32) error {
		if !bytes.Equal(aggregate, make([]byte, len(aggregate))) {
			t.Fatal("aggregate retained until delayed call")
		}
		return base2(h, level, b, n, needed)
	}
	baseClose := api.close
	api.close = func(h windows.Handle) error {
		if !bytes.Equal(aggregate, make([]byte, len(aggregate))) {
			t.Fatal("aggregate not synchronously cleared before close")
		}
		return baseClose(h)
	}
	s, err := startupCollectNativeFixture(t, startupTestServices()[:1], api)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EncodeServiceStartup(s)
	if err != nil || bytes.Contains(b, []byte("private")) || bytes.Contains(b, []byte("account")) || bytes.Contains(b, []byte("password")) || bytes.Contains(b, []byte("0xa5")) {
		t.Fatal("aggregate leaked", string(b), err)
	}
	if len(aggregate) != ServiceStartupMaxConfigBytes || !bytes.Equal(aggregate, make([]byte, len(aggregate))) {
		t.Fatal("buffer not cleared after return")
	}
}

func TestServiceStartupNativeModesAndUnknownDoNotQueryDelayed(t *testing.T) {
	for _, tc := range []struct {
		name          string
		start, kind   uint32
		mode, quality string
		delayed       bool
	}{
		{"manual", windows.SERVICE_DEMAND_START, windows.SERVICE_WIN32_OWN_PROCESS, "manual", "observed", false},
		{"disabled", windows.SERVICE_DISABLED, windows.SERVICE_WIN32_SHARE_PROCESS, "disabled", "observed", false},
		{"automatic", windows.SERVICE_AUTO_START, windows.SERVICE_WIN32_OWN_PROCESS, "automatic", "observed", true},
		{"interactive", windows.SERVICE_AUTO_START, windows.SERVICE_WIN32_OWN_PROCESS | 0x100, "automatic", "observed", true},
		{"user-instance", windows.SERVICE_AUTO_START, windows.SERVICE_WIN32_SHARE_PROCESS | 0x40 | 0x80, "automatic", "observed", true},
		{"boot", 0, windows.SERVICE_WIN32_OWN_PROCESS, "", "unknown", false},
		{"system", 1, windows.SERVICE_WIN32_OWN_PROCESS, "", "unknown", false},
		{"unknown-start", 99, windows.SERVICE_WIN32_OWN_PROCESS, "", "unknown", false},
		{"driver", windows.SERVICE_AUTO_START, windows.SERVICE_KERNEL_DRIVER, "", "unknown", false},
		{"driver-win32-mixed", windows.SERVICE_AUTO_START, windows.SERVICE_KERNEL_DRIVER | windows.SERVICE_WIN32_OWN_PROCESS, "", "unknown", false},
		{"both-win32-bits", windows.SERVICE_AUTO_START, windows.SERVICE_WIN32, "", "unknown", false},
		{"future-type", windows.SERVICE_AUTO_START, windows.SERVICE_WIN32_OWN_PROCESS | 0x1000, "", "unknown", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := startupFakeAPI(t, tc.start)
			q := api.queryConfig
			api.queryConfig = func(h windows.Handle, c *windows.QUERY_SERVICE_CONFIG, n uint32, needed *uint32) error {
				err := q(h, c, n, needed)
				c.ServiceType = tc.kind
				return err
			}
			delayed := 0
			q2 := api.queryConfig2
			api.queryConfig2 = func(h windows.Handle, level uint32, b *byte, n uint32, needed *uint32) error {
				delayed++
				return q2(h, level, b, n, needed)
			}
			s, err := startupCollectNativeFixture(t, startupTestServices()[:1], api)
			if err != nil || len(s.Rows) != 1 || s.Rows[0].StartupQuality != tc.quality || (delayed > 0) != tc.delayed {
				t.Fatal(s, err, delayed)
			}
			r := s.Rows[0]
			if tc.mode == "" {
				if r.StartupMode != nil || r.DelayedAutoQuality != "unknown" {
					t.Fatal(r)
				}
			} else if r.StartupMode == nil || *r.StartupMode != tc.mode {
				t.Fatal(r)
			}
			if tc.mode != "" && !tc.delayed && (r.DelayedAutoStart != nil || r.DelayedAutoQuality != "not-applicable") {
				t.Fatal(r)
			}
		})
	}
}

func TestServiceStartupNativeFailuresBoundsAndBOOL(t *testing.T) {
	for _, stage := range []string{"manager", "service", "config", "delayed"} {
		for _, err := range []error{windows.ERROR_ACCESS_DENIED, windows.ERROR_SERVICE_DOES_NOT_EXIST, windows.ERROR_INSUFFICIENT_BUFFER, errors.New("secret C:\\private account=PRIVATE")} {
			t.Run(stage+"-"+strings.ReplaceAll(err.Error(), "/", "_"), func(t *testing.T) {
				api := startupFakeAPI(t, windows.SERVICE_AUTO_START)
				var aggregate []byte
				closeService, closeManager, queryCount := 0, 0, 0
				api.close = func(h windows.Handle) error {
					if !bytes.Equal(aggregate, make([]byte, len(aggregate))) {
						t.Fatal("failure left aggregate uncleared")
					}
					if h == 1 {
						closeManager++
					}
					if h == 2 {
						closeService++
					}
					return nil
				}
				switch stage {
				case "manager":
					api.openSCM = func(*uint16, *uint16, uint32) (windows.Handle, error) { return 0, err }
				case "service":
					api.openService = func(windows.Handle, *uint16, uint32) (windows.Handle, error) { return 0, err }
				case "config":
					api.queryConfig = func(_ windows.Handle, c *windows.QUERY_SERVICE_CONFIG, n uint32, needed *uint32) error {
						queryCount++
						b := unsafe.Slice((*byte)(unsafe.Pointer(c)), int(n))
						aggregate = b
						for i := range b {
							b[i] = 0xaa
						}
						*needed = ServiceStartupMaxConfigBytes + 1
						return err
					}
				case "delayed":
					api.queryConfig2 = func(windows.Handle, uint32, *byte, uint32, *uint32) error { return err }
				}
				s, e := startupCollectNativeFixture(t, startupTestServices()[:1], api)
				if e != nil || len(s.Rows) != 1 {
					t.Fatal(s, e)
				}
				want := "unavailable"
				if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
					want = "denied"
				}
				if stage == "delayed" {
					if s.Rows[0].StartupQuality != "observed" || s.Rows[0].DelayedAutoQuality != want {
						t.Fatal(s)
					}
				} else if s.Rows[0].StartupQuality != want {
					t.Fatal(s)
				}
				if stage == "manager" {
					if closeService != 0 || closeManager != 0 {
						t.Fatal("closed unowned handle")
					}
				} else if stage == "service" {
					if closeService != 0 || closeManager != 1 {
						t.Fatal("bad failed-open closure")
					}
				} else if closeService != 1 || closeManager != 1 {
					t.Fatal("leaked handle")
				}
				if queryCount > 1 {
					t.Fatal("unbounded resize")
				}
			})
		}
	}
	for _, tc := range []struct {
		name             string
		mutate           func(*serviceStartupNativeAPI)
		startup, delayed string
	}{
		{"config-oversize-success", func(api *serviceStartupNativeAPI) {
			q := api.queryConfig
			api.queryConfig = func(h windows.Handle, c *windows.QUERY_SERVICE_CONFIG, n uint32, needed *uint32) error {
				e := q(h, c, n, needed)
				*needed = n + 1
				return e
			}
		}, "unavailable", "unavailable"},
		{"delayed-oversize-success", func(api *serviceStartupNativeAPI) {
			q := api.queryConfig2
			api.queryConfig2 = func(h windows.Handle, level uint32, b *byte, n uint32, needed *uint32) error {
				e := q(h, level, b, n, needed)
				*needed = n + 1
				return e
			}
		}, "observed", "unavailable"},
		{"bool-nonzero", func(api *serviceStartupNativeAPI) {
			api.queryConfig2 = func(_ windows.Handle, _ uint32, b *byte, _ uint32, needed *uint32) error {
				*(*uint32)(unsafe.Pointer(b)) = 42
				*needed = 4
				return nil
			}
		}, "observed", "observed"},
		{"bool-zero", func(api *serviceStartupNativeAPI) {
			api.queryConfig2 = func(_ windows.Handle, _ uint32, b *byte, _ uint32, needed *uint32) error {
				*(*uint32)(unsafe.Pointer(b)) = 0
				*needed = 4
				return nil
			}
		}, "observed", "observed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			api := startupFakeAPI(t, windows.SERVICE_AUTO_START)
			tc.mutate(&api)
			s, e := startupCollectNativeFixture(t, startupTestServices()[:1], api)
			if e != nil || s.Rows[0].StartupQuality != tc.startup || s.Rows[0].DelayedAutoQuality != tc.delayed {
				t.Fatal(s, e)
			}
			if tc.name == "bool-nonzero" && (s.Rows[0].DelayedAutoStart == nil || !*s.Rows[0].DelayedAutoStart) {
				t.Fatal("BOOL nonzero not true")
			}
			if tc.name == "bool-zero" && (s.Rows[0].DelayedAutoStart == nil || *s.Rows[0].DelayedAutoStart) {
				t.Fatal("observed BOOL zero was lost or treated as delayed")
			}
		})
	}
}

func TestServiceStartupNativeCancellationClosesOwnedHandles(t *testing.T) {
	for _, stage := range []string{"manager", "service", "config", "delayed"} {
		t.Run(stage, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			api := startupFakeAPI(t, windows.SERVICE_AUTO_START)
			managerClosed, serviceClosed, queries := 0, 0, 0
			api.close = func(h windows.Handle) error {
				if h == 1 {
					managerClosed++
				}
				if h == 2 {
					serviceClosed++
				}
				return nil
			}
			switch stage {
			case "manager":
				f := api.openSCM
				api.openSCM = func(m, d *uint16, a uint32) (windows.Handle, error) { h, e := f(m, d, a); cancel(); return h, e }
			case "service":
				f := api.openService
				api.openService = func(m windows.Handle, n *uint16, a uint32) (windows.Handle, error) {
					h, e := f(m, n, a)
					cancel()
					return h, e
				}
			case "config":
				f := api.queryConfig
				api.queryConfig = func(h windows.Handle, c *windows.QUERY_SERVICE_CONFIG, n uint32, k *uint32) error {
					queries++
					e := f(h, c, n, k)
					cancel()
					return e
				}
			case "delayed":
				f := api.queryConfig2
				api.queryConfig2 = func(h windows.Handle, l uint32, b *byte, n uint32, k *uint32) error {
					queries++
					e := f(h, l, b, n, k)
					cancel()
					return e
				}
			}
			_, e := collectServiceStartupUsing(ctx, startupTestServices(), startupTestGeneration, startupTestGrant, startupTestAt, func(ctx context.Context) (ServiceStartupReader, func(), error) {
				return serviceStartupNativeReaderUsing(ctx, api)
			}, serviceStartupCollectionBudget, func() time.Time { return startupTestAt })
			if !errors.Is(e, context.Canceled) || managerClosed != 1 || queries > 1 {
				t.Fatal(e, managerClosed, serviceClosed, queries)
			}
			want := 1
			if stage == "manager" {
				want = 0
			}
			if serviceClosed != want {
				t.Fatal("service handle leak", serviceClosed)
			}
		})
	}
}

func TestServiceStartupNativeInvalidInputsNeverOpen(t *testing.T) {
	api := startupFakeAPI(t, windows.SERVICE_AUTO_START)
	api.openSCM = func(*uint16, *uint16, uint32) (windows.Handle, error) {
		t.Fatal("invalid input opened SCM")
		return 0, nil
	}
	if _, _, err := serviceStartupNativeReaderUsing(nil, api); !errors.Is(err, ErrServiceStartupInvalid) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := serviceStartupNativeReaderUsing(ctx, api); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	api.queryConfig = nil
	if _, _, err := serviceStartupNativeReaderUsing(context.Background(), api); !errors.Is(err, ErrServiceStartupInvalid) {
		t.Fatal(err)
	}
	api = startupFakeAPI(t, windows.SERVICE_AUTO_START)
	api.openService = func(windows.Handle, *uint16, uint32) (windows.Handle, error) {
		t.Fatal("invalid name opened service")
		return 0, nil
	}
	for _, name := range []string{"", "bad\x00name", strings.Repeat("a", MaxTextBytes+1)} {
		if _, err := readServiceStartupNative(context.Background(), 1, name, api); !errors.Is(err, ErrServiceStartupInvalid) {
			t.Fatal(err)
		}
	}
}
