// Package windowsusersoftwarelocal is a fixed, read-only foreground capture
// channel. It shares neither service-action messages nor authority with a broker.
package windowsusersoftwarelocal

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"localrmm/internal/windowsusersoftware"
	"net/url"
	"time"
)

const PipeName = `\\.\pipe\TraceboltWindowsSelectedUserSoftware-v1`
const ServiceName = "TraceboltWindowsAgent"
const IPCVersion = "tracebolt.windows-selected-user-software-local.v1"
const MaxMessageBytes = windowsusersoftware.MaxSourceBytes + 16*1024
const ConversationTimeout = 2 * time.Minute

var ErrBinding = errors.New("selected_user_software_peer_not_verified")
var ErrUnavailable = errors.New("selected_user_software_local_unavailable")
var ErrInvalid = errors.New("selected_user_software_local_invalid")
var ErrDeclined = errors.New("selected_user_software_consent_declined")

// Peer is produced exclusively from a held OS process/token, never wire fields.
// SID remains inside the endpoint. Label is deliberately empty; the handler
// derives a harmless device-scoped display label without account-name lookup.
type Peer struct {
	SID, Label           string
	ProcessID, SessionID uint32
}
type Challenge struct {
	Nonce            string    `json:"nonce"`
	AccountContextID string    `json:"accountContextId"`
	AccountLabel     string    `json:"accountLabel"`
	DeviceID         string    `json:"deviceId"`
	ManagerOrigin    string    `json:"managerOrigin"`
	InsecureHTTP     bool      `json:"insecureHttp"`
	ExpiresAt        time.Time `json:"expiresAt"`
}

// Begin is observational. Reserve must durably consume the exact challenge
// before returning. Abort must preserve its consumed nonce/floor. Submit must
// perform the final live grant and identity check, and persist exact retry bytes.
type Handler interface {
	Begin(context.Context, Peer, string) (Challenge, error)
	Reserve(context.Context, Peer, Challenge) error
	Submit(context.Context, Peer, Challenge, windowsusersoftware.Capture) error
	Abort(context.Context, Peer, Challenge) error
}
type message struct {
	Version   string                       `json:"version"`
	Operation string                       `json:"operation"`
	Nonce     string                       `json:"nonce,omitempty"`
	Challenge *Challenge                   `json:"challenge,omitempty"`
	Capture   *windowsusersoftware.Capture `json:"capture,omitempty"`
}
type channel interface {
	read(context.Context) ([]byte, error)
	write(context.Context, []byte) error
	check() error
}

func encode(m message) ([]byte, error) {
	b, e := json.Marshal(m)
	if e != nil || len(b) > MaxMessageBytes {
		return nil, ErrInvalid
	}
	return b, nil
}
func decode(raw []byte) (message, error) {
	var m message
	if len(raw) == 0 || len(raw) > MaxMessageBytes {
		return m, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&m) != nil || m.Version != IPCVersion {
		return m, ErrInvalid
	}
	canonical, e := encode(m)
	if e != nil || !bytes.Equal(canonical, raw) {
		return message{}, ErrInvalid
	}
	return m, nil
}
func send(ctx context.Context, c channel, m message) error {
	if ctx.Err() != nil || c.check() != nil {
		return ErrBinding
	}
	m.Version = IPCVersion
	b, e := encode(m)
	if e != nil {
		return e
	}
	return c.write(ctx, b)
}
func receive(ctx context.Context, c channel, operation, nonce string) (message, error) {
	raw, e := c.read(ctx)
	if e != nil {
		return message{}, e
	}
	if ctx.Err() != nil || c.check() != nil {
		return message{}, ErrBinding
	}
	m, e := decode(raw)
	if e != nil || m.Operation != operation || m.Nonce != nonce {
		return message{}, ErrInvalid
	}
	return m, nil
}
func validChallenge(c Challenge, nonce string, now time.Time) bool {
	u, e := url.Parse(c.ManagerOrigin)
	return e == nil && u.Host != "" && u.User == nil && (u.Scheme == "https" || u.Scheme == "http" && c.InsecureHTTP) && c.InsecureHTTP == (u.Scheme == "http") && u.RawQuery == "" && u.Fragment == "" && (u.Path == "" || u.Path == "/") && c.DeviceID != "" && len(c.DeviceID) <= 128 && windowsusersoftware.ValidAccount(c.AccountContextID, c.AccountLabel, c.Nonce) && c.Nonce == nonce && windowsusersoftware.ValidTime(c.ExpiresAt) && c.ExpiresAt.After(now) && !c.ExpiresAt.After(now.Add(ConversationTimeout))
}
func serveConversation(ctx context.Context, c channel, h Handler, p Peer) error {
	hello, e := receive(ctx, c, "begin", "")
	if e != nil || hello.Challenge != nil || hello.Capture != nil {
		return ErrInvalid
	}
	var n [32]byte
	if _, e = rand.Read(n[:]); e != nil {
		return ErrUnavailable
	}
	nonce := hex.EncodeToString(n[:])
	ch, e := h.Begin(ctx, p, nonce)
	if e != nil {
		return e
	}
	submitted := false
	defer func() {
		if !submitted && !fatalChannel(c) {
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
			defer cancel()
			_ = h.Abort(cleanup, p, ch)
		}
	}()
	if !validChallenge(ch, nonce, time.Now().UTC()) {
		return ErrInvalid
	}
	ctx, cancel := context.WithDeadline(ctx, ch.ExpiresAt)
	defer cancel()
	if e = send(ctx, c, message{Operation: "challenge", Nonce: nonce, Challenge: &ch}); e != nil {
		return e
	}
	request, e := receive(ctx, c, "reserve", nonce)
	if e != nil || request.Challenge != nil || request.Capture != nil {
		return ErrInvalid
	}
	if e = h.Reserve(ctx, p, ch); e != nil {
		return e
	}
	if e = send(ctx, c, message{Operation: "reserved", Nonce: nonce}); e != nil {
		return e
	}
	request, e = receive(ctx, c, "submit", nonce)
	if e != nil || request.Challenge != nil || request.Capture == nil {
		return ErrInvalid
	}
	cap := *request.Capture
	// Caller may echo the challenge; it cannot select an account or another nonce.
	if cap.AccountContextID != ch.AccountContextID || cap.AccountLabel != ch.AccountLabel || cap.CaptureNonce != nonce {
		return ErrBinding
	}
	if e = h.Submit(ctx, p, ch, cap); e != nil {
		return e
	}
	submitted = true
	if e = send(ctx, c, message{Operation: "accepted", Nonce: nonce}); e != nil {
		return e
	}
	ack, e := receive(ctx, c, "ack", nonce)
	if e != nil || ack.Challenge != nil || ack.Capture != nil {
		return ErrInvalid
	}
	return nil
}
func clientConversation(ctx context.Context, c channel, consent func(context.Context, Challenge) bool, capture func(context.Context) windowsusersoftware.Capture) error {
	if consent == nil || capture == nil {
		return ErrInvalid
	}
	if e := send(ctx, c, message{Operation: "begin"}); e != nil {
		return e
	}
	raw, e := c.read(ctx)
	if e != nil || c.check() != nil {
		return ErrBinding
	}
	m, e := decode(raw)
	if e != nil || m.Operation != "challenge" || m.Challenge == nil || m.Capture != nil || !validChallenge(*m.Challenge, m.Nonce, time.Now().UTC()) {
		return ErrInvalid
	}
	ch := *m.Challenge
	ctx, cancel := context.WithDeadline(ctx, ch.ExpiresAt)
	defer cancel()
	if !consent(ctx, ch) {
		return ErrDeclined
	}
	if ctx.Err() != nil || c.check() != nil {
		return ErrBinding
	}
	if e = send(ctx, c, message{Operation: "reserve", Nonce: ch.Nonce}); e != nil {
		return e
	}
	m, e = receive(ctx, c, "reserved", ch.Nonce)
	if e != nil || m.Challenge != nil || m.Capture != nil {
		return ErrInvalid
	}
	cap := capture(ctx)
	if !cap.Complete && (cap.Reason == "deadline" || cap.Reason == "canceled") {
		return context.DeadlineExceeded
	}
	if ctx.Err() != nil || c.check() != nil {
		return ErrBinding
	}
	cap.AccountContextID = ch.AccountContextID
	cap.AccountLabel = ch.AccountLabel
	cap.CaptureNonce = ch.Nonce
	if e = send(ctx, c, message{Operation: "submit", Nonce: ch.Nonce, Capture: &cap}); e != nil {
		return e
	}
	m, e = receive(ctx, c, "accepted", ch.Nonce)
	if e != nil || m.Challenge != nil || m.Capture != nil {
		return ErrUnavailable
	}
	return send(ctx, c, message{Operation: "ack", Nonce: ch.Nonce})
}

// A failed security-context revert is fatal: do not call even cleanup handlers.
func fatalChannel(c channel) bool { f, ok := c.(interface{ fatal() bool }); return ok && f.fatal() }
