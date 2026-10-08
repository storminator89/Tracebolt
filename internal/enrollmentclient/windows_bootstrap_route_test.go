package enrollmentclient

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
)

// This bounded public-JSON loopback responder has no enrollment authority,
// invitation, keys, identity, persistent state, or access to an external host.
func TestWindowsBootstrapPreSecretChallengeRoute(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != WindowsEnrollmentPathPrefix+"challenge" {
			t.Error("wrong fixed challenge route")
		}
		raw, readErr := io.ReadAll(io.LimitReader(r.Body, 1024))
		if readErr != nil || string(raw) != `{"invitationId":"","claimId":"","purpose":"status"}` || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept") != "application/json" {
			t.Error("unexpected public challenge shape")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"enrollment_proof_rejected","message":"Enrollment proof is invalid or expired."}}`))
	}))
	defer server.Close()
	b := Bootstrap{EnrollmentOrigin: server.URL, Profile: "http-test", CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory}
	legacy, err := lanclient.NewBootstrapHTTPClient(b.EnrollmentOrigin, b.Profile, nil)
	if err != nil {
		t.Fatal("legacy constructor")
	}
	defer legacy.CloseIdleConnections()
	fixed, err := newEnrollmentHTTPClient(b)
	if err != nil {
		t.Fatal("selected constructor")
	}
	defer fixed.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	prompted := false
	s := &session{&sessionData{
		l:    ledger{&ledgerData{Bootstrap: b}},
		wire: &wireClient{client: legacy, origin: server.URL, collectionProfile: b.CollectionProfile},
		opts: Options{Secret: func(context.Context) ([]byte, error) { prompted = true; return nil, ErrInput }},
	}}
	// Reproduce the old pre-prompt rejection twice, without sleeps or retry timers.
	for range 2 {
		_, err = s.status(ctx)
		var failure *httpFailure
		if !errors.Is(err, ErrTransport) || !retryable(err) || errors.As(err, &failure) {
			t.Fatal("old route mismatch not reproduced")
		}
	}
	if calls.Load() != 0 || prompted {
		t.Fatal("legacy route reached responder or prompt")
	}
	s.wire.client = fixed
	_, err = s.status(ctx)
	var failure *httpFailure
	if !errors.As(err, &failure) || failure.status != 401 || errors.Is(err, ErrTransport) {
		t.Fatal("Windows challenge did not receive bounded response")
	}
	// This is the existing preclaim branch's next operation. Deliberately stop in
	// its callback: no invitation is returned, no claim request or key is made.
	if s.claim(ctx) != ErrInput || !prompted || calls.Load() != 1 {
		t.Fatal("preclaim prompt boundary not reached")
	}
}
