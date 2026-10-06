package applicationcheck

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"localrmm/internal/lanconfig"
)

// These fixtures use only injected resolution and in-memory connections. Their
// public-looking addresses must never reach the host resolver or a real dialer.
func dnsTCPTarget(kind string) target {
	t := target{Kind: kind, ID: kind + "-fixture", Host: "private-fixture.example", AllowedAddresses: []string{"8.8.8.8"}}
	if kind == "tcp" {
		t.Port = 8443
	}
	return t
}

func dnsTCPAddresses(raw ...string) []netip.Addr {
	ips := make([]netip.Addr, len(raw))
	for i, s := range raw {
		ips[i] = netip.MustParseAddr(s)
	}
	return ips
}

type dnsTCPConn struct {
	reads, writes, closes atomic.Int32
}

func (c *dnsTCPConn) Read([]byte) (int, error) {
	c.reads.Add(1)
	return 0, errors.New("fixture forbids application reads")
}
func (c *dnsTCPConn) Write([]byte) (int, error) {
	c.writes.Add(1)
	return 0, errors.New("fixture forbids application writes")
}
func (c *dnsTCPConn) Close() error                   { c.closes.Add(1); return nil }
func (*dnsTCPConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (*dnsTCPConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (*dnsTCPConn) SetDeadline(time.Time) error      { return nil }
func (*dnsTCPConn) SetReadDeadline(time.Time) error  { return nil }
func (*dnsTCPConn) SetWriteDeadline(time.Time) error { return nil }

func assertDNSCommonJSON(t *testing.T, r Result) {
	t.Helper()
	encoded, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	if want := []string{"id", "kind", "observedAt", "reason", "state"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("DNS/TCP JSON includes fields outside the common contract: %s", encoded)
	}
	var kind string
	if err := json.Unmarshal(fields["kind"], &kind); err != nil || kind != r.Kind {
		t.Fatalf("wrong JSON kind: %s", encoded)
	}
	for _, forbidden := range []string{"private-fixture.example", "8.8.8.8", "8443", "private resolver detail", "private dial detail"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("result discloses destination or raw error %q: %s", forbidden, encoded)
		}
	}
}

func assertDNSConnectionClosedWithoutTraffic(t *testing.T, conn *dnsTCPConn) {
	t.Helper()
	if conn.closes.Load() != 1 || conn.reads.Load() != 0 || conn.writes.Load() != 0 {
		t.Fatalf("TCP must close once without application I/O: closes=%d reads=%d writes=%d", conn.closes.Load(), conn.reads.Load(), conn.writes.Load())
	}
}

func TestDNSProbeResolvesOnlyReturnedSystemAddresses(t *testing.T) {
	for _, answers := range [][]string{{"8.8.8.8"}, {"9.9.9.9", "8.8.8.8"}} {
		t.Run(strings.Join(answers, ","), func(t *testing.T) {
			trg := dnsTCPTarget("dns")
			trg.AllowedAddresses = []string{"8.8.8.8", "9.9.9.9", "2606:4700:4700::1111"}
			var resolutions atomic.Int32
			p := &probe{resolve: func(ctx context.Context, host string) ([]netip.Addr, error) {
				resolutions.Add(1)
				if host != trg.Host {
					t.Errorf("resolution target=%q, want configured hostname", host)
				}
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > CheckTimeout {
					t.Error("resolution lacks the bounded attempt deadline")
				}
				return dnsTCPAddresses(answers...), nil
			}, dial: func(context.Context, string, string) (net.Conn, error) {
				t.Error("DNS observation dialed a connection")
				return nil, errors.New("forbidden dial")
			}}
			r := p.check(context.Background(), trg, lanconfig.TLS, time.Now())
			if r.Kind != "dns" || r.ID != trg.ID || r.State != "ok" || r.Reason != "dns_resolved" || resolutions.Load() != 1 {
				t.Fatalf("approved system-resolver subset not accepted: %+v, resolutions=%d", r, resolutions.Load())
			}
			assertDNSCommonJSON(t, r)
		})
	}
}

func TestDNSAndTCPAcceptMaximumReturnedAddresses(t *testing.T) {
	for _, kind := range []string{"dns", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			trg := dnsTCPTarget(kind)
			trg.AllowedAddresses = nil
			for i := 1; i <= MaxAddresses; i++ {
				trg.AllowedAddresses = append(trg.AllowedAddresses, fmt.Sprintf("8.8.8.%d", i))
			}
			conn := &dnsTCPConn{}
			var dials int
			p := &probe{resolve: func(context.Context, string) ([]netip.Addr, error) {
				return dnsTCPAddresses(trg.AllowedAddresses...), nil
			}, dial: func(_ context.Context, network, address string) (net.Conn, error) {
				dials++
				if network != "tcp" || address != "8.8.8.1:8443" {
					t.Errorf("wrong numeric destination: %s %s", network, address)
				}
				return conn, nil
			}}
			r := p.check(context.Background(), trg, lanconfig.TLS, time.Now())
			if r.Kind != kind || r.State != "ok" {
				t.Fatalf("maximum approved result set rejected: %+v", r)
			}
			if kind == "dns" && dials != 0 || kind == "tcp" && dials != 1 {
				t.Fatalf("wrong dial count for %s: %d", kind, dials)
			}
			if kind == "tcp" {
				assertDNSConnectionClosedWithoutTraffic(t, conn)
			}
		})
	}
}

func TestDNSAndTCPValidateEveryReturnedAddress(t *testing.T) {
	tests := []struct {
		name    string
		answers []netip.Addr
		allowed []string
		private bool
	}{
		{"unapproved secondary", dnsTCPAddresses("8.8.8.8", "9.9.9.9"), []string{"8.8.8.8"}, false},
		{"unapproved primary", dnsTCPAddresses("9.9.9.9", "8.8.8.8"), []string{"8.8.8.8"}, false},
		{"invalid secondary", append(dnsTCPAddresses("8.8.8.8"), netip.Addr{}), []string{"8.8.8.8"}, true},
	}
	for _, raw := range []string{
		"0.0.0.0", "100.64.0.1", "100.100.100.200", "127.0.0.1", "169.254.169.254", "168.63.129.16",
		"192.0.0.1", "192.0.2.1", "192.31.196.1", "192.52.193.1", "192.88.99.1", "192.175.48.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "224.0.0.1", "255.255.255.255",
		"::", "::1", "fe80::1", "ff02::1", "64:ff9b::808:808", "64:ff9b:1::1", "100::1", "2001::1", "2001:db8::1", "2002::1", "2620:4f:8000::1", "3fff::1", "fd00:ec2::254", "fd20:ce::254", "fe80::1%fixture",
		"::ffff:127.0.0.1", "::ffff:169.254.169.254",
	} {
		tests = append(tests, struct {
			name    string
			answers []netip.Addr
			allowed []string
			private bool
		}{"excluded " + raw, dnsTCPAddresses("8.8.8.8", raw), []string{"8.8.8.8", raw}, true})
	}
	for _, kind := range []string{"dns", "tcp"} {
		for _, tc := range tests {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				trg := dnsTCPTarget(kind)
				trg.AllowedAddresses, trg.AllowPrivateLAN = tc.allowed, tc.private
				p := &probe{resolve: func(context.Context, string) ([]netip.Addr, error) { return tc.answers, nil }, dial: func(context.Context, string, string) (net.Conn, error) {
					t.Error("unsafe answer set caused a dial")
					return nil, nil
				}}
				r := p.check(context.Background(), trg, lanconfig.TLS, time.Now())
				if r.Kind != kind || r.State != "unknown" || r.Reason != "destination_blocked" {
					t.Fatalf("unsafe answer set accepted: %+v", r)
				}
				assertDNSCommonJSON(t, r)
			})
		}
	}
}

func TestDNSAndTCPRequirePrivateLANOptIn(t *testing.T) {
	for _, kind := range []string{"dns", "tcp"} {
		for _, raw := range []string{"10.20.30.40", "172.16.30.40", "192.168.30.40", "fd12:3456::1"} {
			for _, private := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/opt-in=%t", kind, raw, private), func(t *testing.T) {
					trg := dnsTCPTarget(kind)
					trg.AllowedAddresses, trg.AllowPrivateLAN = []string{raw}, private
					conn := &dnsTCPConn{}
					dials := 0
					p := &probe{resolve: func(context.Context, string) ([]netip.Addr, error) { return dnsTCPAddresses(raw), nil }, dial: func(_ context.Context, network, address string) (net.Conn, error) {
						dials++
						if network != "tcp" || address != net.JoinHostPort(raw, "8443") {
							t.Errorf("incorrect private numeric destination %s %s", network, address)
						}
						return conn, nil
					}}
					r := p.check(context.Background(), trg, lanconfig.TLS, time.Now())
					if private {
						if r.State != "ok" {
							t.Fatalf("opted-in private address blocked: %+v", r)
						}
					} else if r.State != "unknown" || r.Reason != "destination_blocked" {
						t.Fatalf("private address accepted without opt-in: %+v", r)
					}
					wantDials := 0
					if private && kind == "tcp" {
						wantDials = 1
						assertDNSConnectionClosedWithoutTraffic(t, conn)
					}
					if dials != wantDials {
						t.Fatalf("got %d dials, want %d", dials, wantDials)
					}
				})
			}
		}
	}
}

func TestDNSAndTCPResolutionFailuresNeverDial(t *testing.T) {
	tooMany := make([]netip.Addr, MaxAddresses+1)
	for i := range tooMany {
		tooMany[i] = netip.MustParseAddr("8.8.8.8")
	}
	for _, kind := range []string{"dns", "tcp"} {
		for _, tc := range []struct {
			name          string
			answers       []netip.Addr
			err           error
			state, reason string
		}{
			{"empty", nil, nil, "network_error", "dns_failed"},
			{"error", nil, errors.New("private resolver detail"), "network_error", "dns_failed"},
			{"partial results plus error", dnsTCPAddresses("8.8.8.8"), errors.New("private resolver detail"), "network_error", "dns_failed"},
			{"too many", tooMany, nil, "unknown", "destination_blocked"},
		} {
			t.Run(kind+"/"+tc.name, func(t *testing.T) {
				p := &probe{resolve: func(context.Context, string) ([]netip.Addr, error) { return tc.answers, tc.err }, dial: func(context.Context, string, string) (net.Conn, error) {
					t.Error("failed resolution dialed")
					return nil, nil
				}}
				r := p.check(context.Background(), dnsTCPTarget(kind), lanconfig.TLS, time.Now())
				if r.Kind != kind || r.State != tc.state || r.Reason != tc.reason {
					t.Fatalf("incorrect resolver failure: %+v", r)
				}
				assertDNSCommonJSON(t, r)
			})
		}
	}
}

func TestTCPProbePinsOneStableAddressAndSendsNoTraffic(t *testing.T) {
	for _, answers := range [][]string{
		{"2606:4700:4700::1111", "9.9.9.9", "8.8.8.8"},
		{"8.8.8.8", "2606:4700:4700::1111", "9.9.9.9"},
		{"9.9.9.9", "8.8.8.8", "2606:4700:4700::1111"},
	} {
		t.Run(strings.Join(answers, ","), func(t *testing.T) {
			trg := dnsTCPTarget("tcp")
			trg.AllowedAddresses = append([]string(nil), answers...)
			resolved := dnsTCPAddresses(answers...)
			original := append([]netip.Addr(nil), resolved...)
			conn := &dnsTCPConn{}
			resolutions, dials := 0, 0
			p := &probe{resolve: func(context.Context, string) ([]netip.Addr, error) { resolutions++; return resolved, nil }, dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				dials++
				if network != "tcp" || address != "8.8.8.8:8443" {
					t.Errorf("dial is not pinned to the stable approved numeric address: %s %s", network, address)
				}
				if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > CheckTimeout {
					t.Error("dial lacks the bounded attempt deadline")
				}
				return conn, nil
			}}
			r := p.check(context.Background(), trg, lanconfig.TLS, time.Now())
			if r.Kind != "tcp" || r.ID != trg.ID || r.State != "ok" || r.Reason != "tcp_connected" || resolutions != 1 || dials != 1 {
				t.Fatalf("incorrect TCP observation: %+v, resolutions=%d dials=%d", r, resolutions, dials)
			}
			if !reflect.DeepEqual(resolved, original) {
				t.Fatal("probe mutated the resolver-owned answer slice")
			}
			assertDNSConnectionClosedWithoutTraffic(t, conn)
			assertDNSCommonJSON(t, r)
		})
	}
}

func TestTCPProbeLiteralHostNeverResolves(t *testing.T) {
	for _, ip := range []string{"8.8.8.8", "2606:4700:4700::1111", "10.20.30.40", "fd12:3456::1"} {
		t.Run(ip, func(t *testing.T) {
			trg := dnsTCPTarget("tcp")
			trg.Host, trg.AllowedAddresses, trg.AllowPrivateLAN = ip, []string{ip}, true
			conn := &dnsTCPConn{}
			dials := 0
			p := &probe{resolve: func(context.Context, string) ([]netip.Addr, error) { t.Error("literal host resolved"); return nil, nil }, dial: func(_ context.Context, network, address string) (net.Conn, error) {
				dials++
				if network != "tcp" || address != net.JoinHostPort(ip, "8443") {
					t.Errorf("incorrect literal numeric destination: %s %s", network, address)
				}
				return conn, nil
			}}
			r := p.check(context.Background(), trg, lanconfig.TLS, time.Now())
			if r.State != "ok" || r.Reason != "tcp_connected" || dials != 1 {
				t.Fatalf("literal host failed: %+v, dials=%d", r, dials)
			}
			assertDNSConnectionClosedWithoutTraffic(t, conn)
		})
	}
}

func TestTCPProbeFailuresNeverRetryAndCloseReturnedConnection(t *testing.T) {
	for _, tc := range []struct {
		name     string
		withConn bool
		err      error
	}{
		{"refused", false, errors.New("private dial detail")},
		{"nil connection without error", false, nil},
		{"connection plus error", true, errors.New("private dial detail")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := &dnsTCPConn{}
			dials := 0
			p := &probe{resolve: func(context.Context, string) ([]netip.Addr, error) { return dnsTCPAddresses("9.9.9.9", "8.8.8.8"), nil }, dial: func(_ context.Context, network, address string) (net.Conn, error) {
				dials++
				if network != "tcp" || address != "8.8.8.8:8443" {
					t.Errorf("unexpected fallback destination: %s %s", network, address)
				}
				if tc.withConn {
					return conn, tc.err
				}
				return nil, tc.err
			}}
			trg := dnsTCPTarget("tcp")
			trg.AllowedAddresses = []string{"8.8.8.8", "9.9.9.9"}
			r := p.check(context.Background(), trg, lanconfig.TLS, time.Now())
			if r.Kind != "tcp" || r.State != "network_error" || r.Reason != "tcp_failed" || dials != 1 {
				t.Fatalf("failed dial retried or misclassified: %+v, dials=%d", r, dials)
			}
			if tc.withConn {
				assertDNSConnectionClosedWithoutTraffic(t, conn)
			}
			assertDNSCommonJSON(t, r)
		})
	}
}

func TestDNSAndTCPRevalidateEachObservation(t *testing.T) {
	for _, kind := range []string{"dns", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			resolutions, dials := 0, 0
			conn := &dnsTCPConn{}
			p := &probe{resolve: func(context.Context, string) ([]netip.Addr, error) {
				resolutions++
				if resolutions == 1 {
					return dnsTCPAddresses("8.8.8.8"), nil
				}
				return dnsTCPAddresses("8.8.8.8", "127.0.0.1"), nil
			}, dial: func(context.Context, string, string) (net.Conn, error) { dials++; return conn, nil }}
			trg := dnsTCPTarget(kind)
			first := p.check(context.Background(), trg, lanconfig.TLS, time.Now())
			second := p.check(context.Background(), trg, lanconfig.TLS, time.Now())
			if first.State != "ok" || second.State != "unknown" || second.Reason != "destination_blocked" || resolutions != 2 {
				t.Fatalf("changed DNS answer reused prior approval: first=%+v second=%+v resolutions=%d", first, second, resolutions)
			}
			wantDials := 0
			if kind == "tcp" {
				wantDials = 1
				assertDNSConnectionClosedWithoutTraffic(t, conn)
			}
			if dials != wantDials {
				t.Fatalf("rebound destination dialed: %d dials", dials)
			}
		})
	}
}

func TestDNSAndTCPCancellationRejectsLateSuccess(t *testing.T) {
	for _, kind := range []string{"dns", "tcp"} {
		for _, phase := range []string{"before resolution", "resolution", "dial"} {
			if kind == "dns" && phase == "dial" {
				continue
			}
			t.Run(kind+"/"+phase, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				if phase == "before resolution" {
					cancel()
				}
				resolutions, dials := 0, 0
				conn := &dnsTCPConn{}
				p := &probe{resolve: func(context.Context, string) ([]netip.Addr, error) {
					resolutions++
					if phase == "resolution" {
						cancel()
					}
					return dnsTCPAddresses("8.8.8.8"), nil
				}, dial: func(context.Context, string, string) (net.Conn, error) {
					dials++
					cancel()
					return conn, nil
				}}
				r := p.check(ctx, dnsTCPTarget(kind), lanconfig.TLS, time.Now())
				if r.Kind != kind || r.State != "unknown" || r.Reason != "cancelled" {
					t.Fatalf("cancelled operation retained success: %+v", r)
				}
				if phase == "before resolution" && resolutions != 0 || phase != "dial" && dials != 0 {
					t.Fatalf("cancellation continued into network work: resolutions=%d dials=%d", resolutions, dials)
				}
				if phase == "dial" {
					if dials != 1 {
						t.Fatalf("expected one cancelled dial, got %d", dials)
					}
					assertDNSConnectionClosedWithoutTraffic(t, conn)
				}
				assertDNSCommonJSON(t, r)
			})
		}
	}
}

func TestDNSAndTCPDeadlinesRejectLateCompletion(t *testing.T) {
	for _, kind := range []string{"dns", "tcp"} {
		for _, phase := range []string{"resolution", "dial"} {
			if kind == "dns" && phase == "dial" {
				continue
			}
			for _, parentDeadline := range []bool{false, true} {
				for _, lateSuccess := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/parent=%t/success=%t", kind, phase, parentDeadline, lateSuccess), func(t *testing.T) {
						synctest.Test(t, func(t *testing.T) {
							ctx := context.Background()
							if parentDeadline {
								var cancel context.CancelFunc
								ctx, cancel = context.WithTimeout(ctx, time.Second)
								defer cancel()
							}
							conn := &dnsTCPConn{}
							dials := 0
							p := &probe{resolve: func(attempt context.Context, _ string) ([]netip.Addr, error) {
								if phase == "resolution" {
									<-attempt.Done()
									if !lateSuccess {
										return nil, attempt.Err()
									}
								}
								return dnsTCPAddresses("8.8.8.8"), nil
							}, dial: func(attempt context.Context, _, _ string) (net.Conn, error) {
								dials++
								<-attempt.Done()
								if lateSuccess {
									return conn, nil
								}
								return conn, attempt.Err()
							}}
							r := p.check(ctx, dnsTCPTarget(kind), lanconfig.TLS, time.Now())
							wantState, wantReason := "network_error", "timeout"
							if parentDeadline {
								wantState, wantReason = "unknown", "cancelled"
							}
							if r.Kind != kind || r.State != wantState || r.Reason != wantReason {
								t.Fatalf("expired operation accepted or misclassified: %+v", r)
							}
							if phase == "resolution" && dials != 0 {
								t.Fatalf("late resolution caused %d dial(s)", dials)
							}
							if phase == "dial" {
								if dials != 1 {
									t.Fatalf("expired dial retried %d times", dials)
								}
								assertDNSConnectionClosedWithoutTraffic(t, conn)
							}
							assertDNSCommonJSON(t, r)
						})
					})
				}
			}
		}
	}
}

func TestTCPResolutionAndDialShareOneDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		start := time.Now()
		conn := &dnsTCPConn{}
		var resolutionDeadline time.Time
		p := &probe{resolve: func(ctx context.Context, _ string) ([]netip.Addr, error) {
			var ok bool
			resolutionDeadline, ok = ctx.Deadline()
			if !ok || !resolutionDeadline.Equal(start.Add(CheckTimeout)) {
				t.Error("resolver did not receive the check deadline")
			}
			time.Sleep(3 * time.Second)
			return dnsTCPAddresses("8.8.8.8"), nil
		}, dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			deadline, ok := ctx.Deadline()
			if !ok || !deadline.Equal(resolutionDeadline) || time.Until(deadline) != CheckTimeout-3*time.Second {
				t.Error("dial reset the shared timeout budget")
			}
			<-ctx.Done()
			return conn, nil
		}}
		r := p.check(context.Background(), dnsTCPTarget("tcp"), lanconfig.TLS, start)
		if r.State != "network_error" || r.Reason != "timeout" || time.Since(start) != CheckTimeout {
			t.Fatalf("DNS and TCP did not share one bounded observation: %+v, elapsed=%s", r, time.Since(start))
		}
		assertDNSConnectionClosedWithoutTraffic(t, conn)
	})
}

func TestDNSAndTCPJSONExcludesHTTPFieldsEvenIfPopulated(t *testing.T) {
	for _, kind := range []string{"dns", "tcp"} {
		t.Run(kind, func(t *testing.T) {
			observed := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
			status := 200
			r := Result{Kind: kind, ID: "fixture", State: "ok", Reason: kind + "_fixture", ObservedAt: &observed,
				Scheme: "https", HTTPStatus: &status, TLS: TLSResult{State: "valid", ExpiresAt: &observed}}
			assertDNSCommonJSON(t, r)
		})
	}
}
