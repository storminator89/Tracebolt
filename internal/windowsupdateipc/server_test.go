package windowsupdateipc

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"localrmm/internal/actionpermit"
	job "localrmm/internal/windowsupdatejob"
	"strings"
	"sync"
	"testing"
	"time"
)

type serverStore struct {
	files map[string][]byte
	mu    sync.Mutex
}

func (s *serverStore) Read(n string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.files[n]
	if !ok {
		return nil, job.ErrIntegrity
	}
	return bytes.Clone(b), nil
}
func (s *serverStore) Write(n string, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[n] = bytes.Clone(b)
	return nil
}
func (*serverStore) Verify() error { return nil }

type serverAuthority struct{ current job.Current }

func (a serverAuthority) WithCurrent(ctx context.Context, b job.Binding, fn func(job.Current) error) error {
	if e := ctx.Err(); e != nil {
		return e
	}
	return fn(a.current)
}

type serverNative struct {
	ready            job.Readiness
	entered, release chan struct{}
	installs         int
}

func (n *serverNative) PrepareExact(context.Context, job.Selection) (job.PreparedUpdate, error) {
	return n, nil
}
func (n *serverNative) Inspect(context.Context) (job.Readiness, error) { return n.ready, nil }
func (n *serverNative) InstallOnce(ctx context.Context) (job.NativeResult, error) {
	n.installs++
	close(n.entered)
	select {
	case <-n.release:
		return job.NativeResult{OperationResult: 2, RebootRequired: job.No}, nil
	case <-ctx.Done():
		return job.NativeResult{RebootRequired: job.Unknown}, ctx.Err()
	}
}
func (*serverNative) Close() error { return nil }
func TestServerAcknowledgesOnlyDurableConsumeAndDisconnectDoesNotOwnInstall(t *testing.T) {
	peer, key := testPeer()
	manager := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32))
	at := time.Unix(1700000000, 0)
	consent := job.Consent{Version: job.ConsentVersion, Scope: job.Scope, Binding: peer.Binding, Enabled: true, Acknowledged: true, ExpiresAt: at.Unix() + 3600}
	record, e := job.NewExecutorRecord(consent, manager.Public().(ed25519.PublicKey), peer.ExecutorPublicKey, at.Unix())
	if e != nil {
		t.Fatal(e)
	}
	recordRaw, _ := job.EncodeExecutorRecord(record)
	consentRaw, _ := json.Marshal(consent)
	store := &serverStore{files: map[string][]byte{"executor.json": recordRaw, "started.json": consentRaw, "receipt.json": consentRaw}}
	ready := job.Readiness{Selection: job.Selection{UpdateID: "11111111-2222-3333-4444-555555555555", Revision: 1}, CapturedAt: at.Unix(), Software: job.Yes, Installed: job.No, Hidden: job.No, Downloaded: job.Yes, EULAAccepted: job.Yes, CanRequestUserInput: job.No, CanRequireSource: job.No, RequiresNetwork: job.No, InstallerBusy: job.No, RebootRequiredBefore: job.No, RebootBehavior: "can", OfflineVerified: job.Yes}
	native := &serverNative{ready: ready, entered: make(chan struct{}), release: make(chan struct{})}
	authority := serverAuthority{job.Current{Binding: peer.Binding, LeafDigest: actionpermit.Digest([]byte("leaf")), LeafGeneration: 1, LeafNotBefore: at.Unix() - 60, LeafNotAfter: at.Unix() + 3600, Enabled: true}}
	x, e := job.OpenExecutor(store, authority, native, key, func() time.Time { return at })
	if e != nil {
		t.Fatal(e)
	}
	defer x.Close()
	s, e := NewServer(context.Background(), x, peer, key, func(context.Context) error { return nil })
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	preview := job.Preview{ID: "update_" + strings.Repeat("5", 32), ActorID: "operator_" + strings.Repeat("6", 32), Binding: peer.Binding, Readiness: ready, CreatedAt: at.Unix(), ExpiresAt: at.Unix() + 60}
	b, _ := json.Marshal(preview)
	preview.Digest = actionpermit.Digest(append([]byte("Tracebolt selected WUA preview v1\x00"), b...))
	permit, e := job.Sign(job.Permit{Version: job.Version, Preview: preview, Sequence: 1, ApprovedAt: at.Unix()}, manager)
	if e != nil {
		t.Fatal(e)
	}
	requestRaw, _ := json.Marshal(request{Version: Version, Operation: "submit", Envelope: permit})
	conn, cancel := context.WithCancel(context.Background())
	out := s.dispatch(conn, requestRaw)
	cancel()
	if out.Error != "" || out.Report != nil || out.Status != nil {
		t.Fatal("submit did not only acknowledge", out)
	}
	persisted, _ := store.Read("executor.json")
	if json.Unmarshal(persisted, &record) != nil || len(record.Attempts) != 1 || !bytes.Equal(record.Attempts[0].Envelope, permit) {
		t.Fatal("ack before durable consume")
	}
	<-native.entered
	statusRequest, _ := json.Marshal(request{Version: Version, Operation: "status"})
	status := s.dispatch(context.Background(), statusRequest)
	if status.Error != "" || status.Status == nil || !status.Status.Attempts[0].Attempted {
		t.Fatal("live status blocked")
	}
	if again := s.dispatch(context.Background(), requestRaw); again.Error == "" {
		t.Fatal("lost submit repeated")
	}
	if strings.Contains(fmt.Sprintf("%+v", s), fmt.Sprint([]byte(key))) {
		t.Fatal("server formatting leaked key")
	}
	close(native.release)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		status = s.dispatch(context.Background(), statusRequest)
		if status.Status != nil && status.Status.Attempts[0].Result != nil {
			if status.Status.Attempts[0].Result.Outcome != "succeeded" {
				t.Fatal("disconnect canceled install")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("independent install did not complete")
}
