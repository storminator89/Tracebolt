//go:build linux

package lanclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"localrmm/internal/journalhelper"
	"localrmm/internal/journalpolicy"
	"localrmm/internal/journalrequest"
	"localrmm/internal/journalstate"
	"localrmm/internal/journalview"
	"localrmm/internal/journalwire"
)

type journalFixture struct {
	s                                 *journalSender
	local                             journalLocal
	now                               time.Time
	record                            journalrequest.Record
	captures, verifies, claims, sends int
	bodies                            [][]byte
	failSend                          bool
	consumed                          bool
}

func journalResponse(t *testing.T, status byte, pd, revision string, payload []byte) journalhelper.Response {
	t.Helper()
	raw := make([]byte, 73+len(payload))
	copy(raw, "TBJ1")
	raw[4] = status
	if status == journalhelper.StatusSnapshot || status == journalhelper.StatusVerified {
		p, _ := hex.DecodeString(strings.TrimPrefix(pd, "sha256:"))
		r, _ := hex.DecodeString(strings.TrimPrefix(revision, "sha256:"))
		copy(raw[5:37], p)
		copy(raw[37:69], r)
	}
	binary.BigEndian.PutUint32(raw[69:73], uint32(len(payload)))
	copy(raw[73:], payload)
	r, e := journalhelper.ReadResponse(bytes.NewReader(raw))
	if e != nil {
		t.Fatal("inert helper frame invalid")
	}
	return r
}
func newJournalFixture(t *testing.T) *journalFixture {
	t.Helper()
	f := &journalFixture{now: time.Now().UTC().Truncate(time.Microsecond), failSend: true}
	m := Material{config: Config{SchemaVersion: CompleteConfigVersion, CollectionProfile: journalpolicy.CollectionProfile, Profile: "tls", ManagerOrigin: "https://manager.example", AgentID: "agent_" + strings.Repeat("a", 32), StateDirectory: t.TempDir()}, binding: strings.Repeat("b", 64), certificate: tls.Certificate{Certificate: [][]byte{[]byte("synthetic-public-leaf")}}}
	f.local = journalLocal{revision: "local-1", policy: journalpolicy.Policy{SchemaVersion: journalpolicy.Version, Scope: journalpolicy.Scope, CollectionProfile: journalpolicy.CollectionProfile, SenderBinding: m.binding, ManagerOrigin: m.config.ManagerOrigin, TransportProfile: "tls", AgentUID: 1001, HelperUID: 1002, AllowedUnits: []string{"example.service"}, MaxWindowSeconds: 3600, MaxLookbackSeconds: 86400, MaxPriority: 7, Enabled: true, ContentAcknowledged: true}}
	var e error
	f.record, e = journalrequest.New(m.config.AgentID, journalLeaf(m), 9, journalview.Query{Unit: "example.service", Start: f.now.Add(-time.Minute), End: f.now, MaxPriority: 6}, f.now)
	if e != nil {
		t.Fatal("inert query fixture")
	}
	state, e := journalstate.Initialize(context.Background(), journalStateDirectory(m.config), m.binding)
	if e != nil {
		t.Fatal(e)
	}
	f.s = &journalSender{material: m, state: state, now: func() time.Time { return f.now }, local: func(Material) (journalLocal, error) { return f.local, nil }}
	f.s.helper = func(_ context.Context, _ journalLocal, req journalhelper.Request) (journalhelper.Response, error) {
		permit, e := journalpolicy.AuthorizeBound(f.local.policy, journalContext(m, f.local), req.Query, req.PolicyGeneration, f.now)
		if e != nil {
			return journalhelper.Response{}, e
		}
		rev := "sha256:" + strings.Repeat("c", 64)
		if req.Operation == journalhelper.VerifyOperation {
			f.verifies++
			return journalResponse(t, journalhelper.StatusVerified, permit.PolicyDigest(), rev, nil), nil
		}
		f.captures++
		// Read metadata only. The helper callback runs under State.Use's lock.
		raw, e := os.ReadFile(filepath.Join(journalStateDirectory(m.config), "journal-consumption.json"))
		if e != nil || !bytes.Contains(raw, []byte(`"sequence":9`)) || !f.consumed {
			t.Fatal("helper preceded both durable claims")
		}
		snapshot, e := journalview.Parse(context.Background(), req.Query, f.now, strings.NewReader(""))
		if e != nil {
			t.Fatal(e)
		}
		snapshot.Rows = []journalview.Row{{Timestamp: req.Query.Start, Unit: req.Query.Unit, Priority: 3, Message: "synthetic journal message"}}
		snapshot.ObservedCount = 1
		b, e := journalview.Encode(snapshot)
		if e != nil {
			t.Fatal(e)
		}
		return journalResponse(t, journalhelper.StatusSnapshot, permit.PolicyDigest(), rev, b), nil
	}
	f.s.exchange = func(_ context.Context, path string, _ uint64, b []byte) ([]byte, int, error) {
		switch path {
		case journalwire.PeekPath:
			raw, _ := json.Marshal(f.record.Description)
			return raw, 200, nil
		case journalwire.ClaimPath:
			f.claims++
			claim, e := journalwire.DecodeClaim(b)
			if e != nil {
				t.Fatal(e)
			}
			if f.consumed {
				return nil, 409, nil
			}
			f.consumed = true
			raw, _ := json.Marshal(journalrequest.Grant{Description: f.record.Description, PolicyDigest: claim.PolicyDigest, ClaimedAt: f.now})
			return raw, 200, nil
		case journalwire.ResultPath:
			f.sends++
			f.bodies = append(f.bodies, bytes.Clone(b))
			if f.failSend {
				return nil, 503, nil
			}
			result, e := journalwire.DecodeResult(b)
			if e != nil {
				t.Fatal(e)
			}
			digest, _ := journalview.SnapshotDigest(result.Snapshot)
			raw, _ := json.Marshal(journalrequest.Receipt{Identity: result.Claim.Identity, PolicyDigest: result.Claim.PolicyDigest, ResultDigest: digest, AcceptedAt: f.now, ExpiresAt: f.record.Description.ExpiresAt})
			return raw, 200, nil
		case journalwire.StatusPath:
			return nil, 200, nil
		}
		t.Fatal("unexpected path")
		return nil, 0, errors.New("inert")
	}
	t.Cleanup(f.s.Close)
	return f
}
func TestJournalNativeConsumesThenExactMemoryRetry(t *testing.T) {
	f := newJournalFixture(t)
	if got := f.s.Run(context.Background()); got != "pending_retained" {
		t.Fatal(got)
	}
	if f.captures != 1 || f.claims != 1 || f.verifies != 1 || f.sends != 1 {
		t.Fatal("unexpected first attempt counts")
	}
	f.now = f.now.Add(time.Second)
	f.failSend = false
	if got := f.s.Run(context.Background()); got != "acknowledged" {
		t.Fatal(got)
	}
	if f.captures != 1 || f.claims != 1 || f.verifies != 2 || f.sends != 2 || !bytes.Equal(f.bodies[0], f.bodies[1]) || f.s.pending != nil {
		t.Fatal("retry recaptured, changed exact bytes, or missed verification")
	}
	raw, _ := os.ReadFile(filepath.Join(journalStateDirectory(f.s.material.config), "journal-consumption.json"))
	if bytes.Contains(raw, []byte("synthetic journal")) || bytes.Contains(raw, []byte("example.service")) {
		t.Fatal("source content entered durable marker")
	}
}
func TestJournalNativeRestartNeverRecapturesConsumedGrant(t *testing.T) {
	f := newJournalFixture(t)
	if f.s.Run(context.Background()) != "pending_retained" {
		t.Fatal("first")
	}
	f.s.Close()
	f.s.state = nil
	if got := f.s.Run(context.Background()); got != "result_lost" {
		t.Fatal(got)
	}
	if f.captures != 1 || f.claims != 1 || f.sends != 1 {
		t.Fatal("restart recaptured or retried lost body")
	}
}
func TestJournalNativePolicyDisableAndRevisionSuppressUnsent(t *testing.T) {
	for _, mode := range []string{"disabled", "revision", "helper-revision"} {
		t.Run(mode, func(t *testing.T) {
			f := newJournalFixture(t)
			f.s.Run(context.Background())
			switch mode {
			case "disabled":
				f.s.local = func(Material) (journalLocal, error) { return journalLocal{}, errJournalDisabled }
			case "revision":
				f.local.revision = "local-2"
			case "helper-revision":
				f.s.helper = func(context.Context, journalLocal, journalhelper.Request) (journalhelper.Response, error) {
					return journalResponse(t, journalhelper.StatusDenied, "", "", nil), nil
				}
			}
			got := f.s.Run(context.Background())
			if got != "disabled" && got != "denied" {
				t.Fatal(got)
			}
			if f.s.pending != nil || f.sends != 1 || f.captures != 1 {
				t.Fatal("revoked content escaped")
			}
		})
	}
}
func TestJournalNativeExpiryNeverRefreshesOrRecaptures(t *testing.T) {
	f := newJournalFixture(t)
	f.s.Run(context.Background())
	f.now = f.record.Description.ExpiresAt
	if f.s.Run(context.Background()) != "expired" || f.s.pending != nil || f.captures != 1 || f.sends != 1 {
		t.Fatal("expiry bypass")
	}
}
func TestJournalNativeRejectsDisallowedUnitBeforeClaim(t *testing.T) {
	f := newJournalFixture(t)
	f.local.policy.AllowedUnits = []string{"other.service"}
	if f.s.Run(context.Background()) != "denied" || f.claims != 0 || f.captures != 0 {
		t.Fatal("local allowlist bypass")
	}
}
func TestJournalNativeDefaultOffDoesNoWork(t *testing.T) {
	f := newJournalFixture(t)
	f.s.local = func(Material) (journalLocal, error) { return journalLocal{}, errJournalDisabled }
	f.s.exchange = func(context.Context, string, uint64, []byte) ([]byte, int, error) {
		t.Fatal("disabled journal contacted manager")
		return nil, 0, nil
	}
	if f.s.Run(context.Background()) != "disabled" || f.captures != 0 {
		t.Fatal("default-off bypass")
	}
}
func TestJournalNativeMissingStateNeverInitializes(t *testing.T) {
	f := newJournalFixture(t)
	f.s.Close()
	f.s.state = nil
	f.s.material.config.StateDirectory = t.TempDir()
	if f.s.Run(context.Background()) != "state_unavailable" || f.claims != 0 {
		t.Fatal("missing floor adopted")
	}
	if _, e := os.Stat(journalStateDirectory(f.s.material.config)); !os.IsNotExist(e) {
		t.Fatal("missing state initialized")
	}
}
func TestJournalNativeLostClaimNeverCaptures(t *testing.T) {
	f := newJournalFixture(t)
	orig := f.s.exchange
	f.s.exchange = func(c context.Context, p string, n uint64, b []byte) ([]byte, int, error) {
		raw, code, e := orig(c, p, n, b)
		if p == journalwire.ClaimPath {
			return nil, 0, errors.New("lost receipt")
		}
		return raw, code, e
	}
	if f.s.Run(context.Background()) != "result_lost" || f.captures != 0 {
		t.Fatal("lost claim invoked helper")
	}
	if f.s.Run(context.Background()) != "result_lost" || f.captures != 0 {
		t.Fatal("second claim recollected")
	}
}
func TestJournalNativeHelperFailureConsumedWithoutRetry(t *testing.T) {
	f := newJournalFixture(t)
	f.s.helper = func(context.Context, journalLocal, journalhelper.Request) (journalhelper.Response, error) {
		f.captures++
		return journalhelper.Response{}, errors.New("synthetic source unavailable")
	}
	if f.s.Run(context.Background()) != "helper_unavailable" {
		t.Fatal("helper result")
	}
	if f.s.Run(context.Background()) != "result_lost" || f.captures != 1 {
		t.Fatal("helper failure recaptured")
	}
}
func TestJournalNativeFormattingRedactsMemory(t *testing.T) {
	f := newJournalFixture(t)
	f.s.Run(context.Background())
	for _, v := range []any{f.s, *f.s, f.s.pending, *f.s.pending} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%p"} {
			out := fmt.Sprintf(format, v)
			if strings.Contains(out, "synthetic journal") || strings.Contains(out, "73796e746865746963") {
				t.Fatal("diagnostic content leak")
			}
		}
	}
}
func TestJournalNativeNonOKNeverAcceptsForgedReceipt(t *testing.T) {
	f := newJournalFixture(t)
	orig := f.s.exchange
	f.s.exchange = func(c context.Context, p string, n uint64, b []byte) ([]byte, int, error) {
		raw, code, e := orig(c, p, n, b)
		if p == journalwire.ResultPath {
			return raw, http.StatusUnauthorized, e
		}
		return raw, code, e
	}
	if f.s.Run(context.Background()) != "pending_retained" || f.s.pending == nil {
		t.Fatal("nonOK cleared body")
	}
}

func TestJournalNativePruneWithoutNetworkOrHelper(t *testing.T) {
	f := newJournalFixture(t)
	f.s.Run(context.Background())
	f.now = f.record.Description.ExpiresAt
	if f.s.prune() != "expired" || f.s.pending != nil || f.sends != 1 || f.captures != 1 || f.verifies != 1 {
		t.Fatal("synchronous expiry prune failed")
	}
}

func TestJournalPendingHasSingleJoinedExpiryWithoutReread(t *testing.T) {
	p := &journalPending{memory: &journalMemory{raw: []byte("synthetic retained result")}, done: make(chan struct{}), grant: journalrequest.Grant{Description: journalrequest.Description{ExpiresAt: time.Now().Add(10 * time.Millisecond)}}}
	p.startExpiry()
	select {
	case <-p.done:
	case <-time.After(time.Second):
		t.Fatal("expiry callback did not finish")
	}
	p.memory.mu.Lock()
	gone := p.memory.expired && len(p.memory.raw) == 0
	p.memory.mu.Unlock()
	if !gone {
		t.Fatal("expired body retained")
	}
	s := &journalSender{pending: p}
	s.discard()
	s.Close()
}
func TestJournalPendingCloseStopsAndJoinsTimer(t *testing.T) {
	p := &journalPending{memory: &journalMemory{raw: []byte("synthetic retained result")}, done: make(chan struct{}), grant: journalrequest.Grant{Description: journalrequest.Description{ExpiresAt: time.Now().Add(time.Hour)}}}
	p.startExpiry()
	s := &journalSender{pending: p}
	s.Close()
	select {
	case <-p.done:
	default:
		t.Fatal("stopped expiry callback not joined")
	}
	if len(p.memory.raw) != 0 || s.pending != nil {
		t.Fatal("Close retained body")
	}
}
