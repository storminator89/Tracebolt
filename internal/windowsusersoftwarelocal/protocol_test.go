package windowsusersoftwarelocal

import (
	"context"
	"errors"
	"localrmm/internal/windowsusersoftware"
	"strings"
	"testing"
	"time"
)

type fixtureChannel struct {
	in         [][]byte
	out        []message
	checkError error
	onWrite    func(message)
	readHook   func() ([]byte, error)
}

func (f *fixtureChannel) read(context.Context) ([]byte, error) {
	if f.readHook != nil {
		return f.readHook()
	}
	if len(f.in) == 0 {
		return nil, ErrUnavailable
	}
	v := f.in[0]
	f.in = f.in[1:]
	return v, nil
}
func (f *fixtureChannel) write(_ context.Context, b []byte) error {
	m, e := decode(b)
	if e != nil {
		return e
	}
	f.out = append(f.out, m)
	if f.onWrite != nil {
		f.onWrite(m)
	}
	return nil
}
func (f *fixtureChannel) check() error { return f.checkError }
func wire(m message) []byte            { m.Version = IPCVersion; b, _ := encode(m); return b }
func challenge(n string) Challenge {
	return Challenge{Nonce: n, AccountContextID: strings.Repeat("a", 64), AccountLabel: "Selected account aaaaaaaa", DeviceID: "agent_test", ManagerOrigin: "https://manager.example", ExpiresAt: time.Now().UTC().Add(time.Minute)}
}

type fixtureHandler struct {
	begun, reserved, submitted, aborted int
	reserveError, errorSubmit           error
	challenge                           Challenge
	peer                                Peer
	capture                             windowsusersoftware.Capture
}

func (h *fixtureHandler) Begin(_ context.Context, p Peer, n string) (Challenge, error) {
	h.begun++
	h.peer = p
	h.challenge = challenge(n)
	return h.challenge, nil
}
func (h *fixtureHandler) Reserve(context.Context, Peer, Challenge) error {
	h.reserved++
	return h.reserveError
}
func (h *fixtureHandler) Submit(_ context.Context, p Peer, c Challenge, v windowsusersoftware.Capture) error {
	h.submitted++
	h.capture = v
	return h.errorSubmit
}
func (h *fixtureHandler) Abort(context.Context, Peer, Challenge) error { h.aborted++; return nil }
func TestConversationRequiresConsentReserveAndSameConnectionNonce(t *testing.T) {
	h := &fixtureHandler{}
	c := &fixtureChannel{in: [][]byte{wire(message{Operation: "begin"})}}
	c.onWrite = func(m message) {
		switch m.Operation {
		case "challenge":
			c.in = append(c.in, wire(message{Operation: "reserve", Nonce: m.Nonce}))
		case "reserved":
			v := windowsusersoftware.Capture{AccountContextID: h.challenge.AccountContextID, AccountLabel: h.challenge.AccountLabel, CaptureNonce: m.Nonce}
			c.in = append(c.in, wire(message{Operation: "submit", Nonce: m.Nonce, Capture: &v}))
		case "accepted":
			c.in = append(c.in, wire(message{Operation: "ack", Nonce: m.Nonce}))
		}
	}
	peer := Peer{SID: "S-1-5-21-1", ProcessID: 42, SessionID: 1}
	if e := serveConversation(context.Background(), c, h, peer); e != nil {
		t.Fatal(e)
	}
	if h.begun != 1 || h.reserved != 1 || h.submitted != 1 || h.aborted != 0 || h.peer != peer {
		t.Fatalf("wrong lifecycle: %+v", h)
	}
}
func TestEveryUnsubmittedBeginReleasesChallengeAndConsumedReservation(t *testing.T) {
	for _, stage := range []string{"decline", "stale_nonce", "reserve_failure", "account_swap", "peer_changed", "submit_failure"} {
		t.Run(stage, func(t *testing.T) {
			h := &fixtureHandler{}
			c := &fixtureChannel{in: [][]byte{wire(message{Operation: "begin"})}}
			c.onWrite = func(m message) {
				switch m.Operation {
				case "challenge":
					if stage == "decline" {
						return
					}
					nonce := m.Nonce
					if stage == "stale_nonce" {
						nonce = strings.Repeat("0", 64)
					}
					if stage == "reserve_failure" {
						h.reserveError = ErrUnavailable
					}
					if stage == "peer_changed" {
						c.checkError = ErrBinding
					}
					c.in = append(c.in, wire(message{Operation: "reserve", Nonce: nonce}))
				case "reserved":
					v := windowsusersoftware.Capture{AccountContextID: h.challenge.AccountContextID, AccountLabel: h.challenge.AccountLabel, CaptureNonce: m.Nonce}
					if stage == "account_swap" {
						v.AccountContextID = strings.Repeat("b", 64)
					}
					if stage == "submit_failure" {
						h.errorSubmit = ErrUnavailable
					}
					c.in = append(c.in, wire(message{Operation: "submit", Nonce: m.Nonce, Capture: &v}))
				}
			}
			if e := serveConversation(context.Background(), c, h, Peer{}); e == nil {
				t.Fatal("unexpected success")
			}
			if h.aborted != 1 {
				t.Fatalf("abort count %d", h.aborted)
			}
		})
	}
}
func TestClientDeclineDoesNotReserveOrCapture(t *testing.T) {
	ch := challenge(strings.Repeat("a", 64))
	c := &fixtureChannel{in: [][]byte{wire(message{Operation: "challenge", Nonce: ch.Nonce, Challenge: &ch})}}
	called := false
	e := clientConversation(context.Background(), c, func(context.Context, Challenge) bool { return false }, func(context.Context) windowsusersoftware.Capture { called = true; return windowsusersoftware.Capture{} })
	if !errors.Is(e, ErrDeclined) || called || len(c.out) != 1 || c.out[0].Operation != "begin" {
		t.Fatalf("consent bypass: %v %v %+v", e, called, c.out)
	}
}
func TestClientNativeTimeoutExitsWithoutFurtherReadsOrSubmit(t *testing.T) {
	ch := challenge(strings.Repeat("a", 64))
	c := &fixtureChannel{in: [][]byte{wire(message{Operation: "challenge", Nonce: ch.Nonce, Challenge: &ch}), wire(message{Operation: "reserved", Nonce: ch.Nonce})}}
	e := clientConversation(context.Background(), c, func(context.Context, Challenge) bool { return true }, func(context.Context) windowsusersoftware.Capture {
		c.checkError = ErrBinding
		return windowsusersoftware.Capture{Reason: "deadline"}
	})
	if !errors.Is(e, context.DeadlineExceeded) || len(c.out) != 2 {
		t.Fatalf("timeout did not exit immediately: %v %+v", e, c.out)
	}
}
func TestWireRejectsUnknownDuplicateOversizeAndNoncanonical(t *testing.T) {
	good := string(wire(message{Operation: "begin"}))
	for _, raw := range []string{good + " ", strings.Replace(good, `"operation":"begin"`, `"operation":"begin","operation":"begin"`, 1), strings.Replace(good, "}", `,"sid":"S-1-5-18"}`, 1), strings.Repeat("x", MaxMessageBytes+1)} {
		if _, e := decode([]byte(raw)); e == nil {
			t.Fatal("accepted malformed wire")
		}
	}
}
func TestChallengeExpiryAndRecipient(t *testing.T) {
	n := strings.Repeat("a", 64)
	now := time.Now().UTC()
	good := challenge(n)
	if !validChallenge(good, n, now) {
		t.Fatal("valid challenge rejected")
	}
	for _, mutate := range []func(*Challenge){func(c *Challenge) { c.ExpiresAt = now }, func(c *Challenge) { c.ExpiresAt = now.Add(ConversationTimeout + time.Second) }, func(c *Challenge) { c.ManagerOrigin = "http://manager.example" }, func(c *Challenge) { c.ManagerOrigin = "https://name:password@manager.example" }, func(c *Challenge) { c.Nonce = strings.Repeat("b", 64) }, func(c *Challenge) { c.ManagerOrigin = "https://manager.example/?secret=x" }} {
		bad := good
		mutate(&bad)
		if validChallenge(bad, n, now) {
			t.Fatalf("accepted bad challenge: %+v", bad)
		}
	}
	good.InsecureHTTP = true
	good.ManagerOrigin = "http://manager.example"
	if !validChallenge(good, n, now) {
		t.Fatal("explicit HTTP disclosure rejected")
	}
}

type fatalFixtureChannel struct {
	fixtureChannel
	failed bool
}

func (c *fatalFixtureChannel) fatal() bool { return c.failed }
func TestFatalIdentityFailureNeverCallsAdmissionOrCleanupHandler(t *testing.T) {
	h := &fixtureHandler{}
	c := &fatalFixtureChannel{fixtureChannel: fixtureChannel{in: [][]byte{wire(message{Operation: "begin"})}}}
	c.onWrite = func(m message) {
		if m.Operation == "challenge" {
			c.failed = true
			c.checkError = ErrBinding
			c.in = append(c.in, wire(message{Operation: "reserve", Nonce: m.Nonce}))
		}
	}
	if e := serveConversation(context.Background(), c, h, Peer{}); e == nil {
		t.Fatal("fatal peer accepted")
	}
	if h.begun != 1 || h.reserved != 0 || h.submitted != 0 || h.aborted != 0 {
		t.Fatalf("handler ran after fatal identity error: %+v", h)
	}
}
