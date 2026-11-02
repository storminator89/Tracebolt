//go:build linux

package enrollmenttransport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"golang.org/x/crypto/argon2"
	"io"
	"localrmm/internal/operatorauth"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Only the real TCP socket is stalled. Journal, admission, claim consumption,
// response buffering and flush all use their production implementations.
type serviceJournalSocket struct {
	net.Conn
	entered chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (c *serviceJournalSocket) Write(p []byte) (int, error) {
	c.once.Do(func() { close(c.entered); <-c.resume })
	return c.Conn.Write(p)
}

type serviceJournalListener struct {
	net.Listener
	accepted chan *serviceJournalSocket
}

func (l *serviceJournalListener) Accept() (net.Conn, error) {
	c, e := l.Listener.Accept()
	if e != nil {
		return nil, e
	}
	s := &serviceJournalSocket{Conn: c, entered: make(chan struct{}), resume: make(chan struct{})}
	l.accepted <- s
	return s, nil
}

func TestJournalAccountRevocationFencesRealServiceSocketAndRestart(t *testing.T) {
	ctx := context.Background()
	salt := make([]byte, 16)
	passwordBytes := make([]byte, 24)
	if _, e := rand.Read(salt); e != nil {
		t.Fatal(e)
	}
	if _, e := rand.Read(passwordBytes); e != nil {
		t.Fatal(e)
	}
	password := base64.RawStdEncoding.EncodeToString(passwordBytes)
	digest := argon2.IDKey([]byte(password), salt, 2, 65536, 1, 32)
	hash := fmt.Sprintf("$argon2id$v=19$m=65536,t=2,p=1$%s$%s", base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(digest))
	const authority = "authority_11111111111111111111111111111111"
	const adminID = "operator_00000000000000000000000000000001"
	const workerID = "operator_00000000000000000000000000000002"
	const otherID = "operator_00000000000000000000000000000003"
	records := []operatorauth.AccountRecord{}
	for _, v := range []struct {
		id, name string
		caps     []operatorauth.Capability
	}{{adminID, "admin", []operatorauth.Capability{operatorauth.Read, operatorauth.ManageAccounts}}, {workerID, "worker", []operatorauth.Capability{operatorauth.Read, operatorauth.RestartService}}, {otherID, "other", []operatorauth.Capability{operatorauth.Read, operatorauth.RestartService}}} {
		records = append(records, operatorauth.AccountRecord{Operator: operatorauth.Operator{ID: v.id, Username: v.name, PasswordHash: hash, Capabilities: v.caps}, Revision: 1})
	}
	dir := filepath.Join(t.TempDir(), "private")
	if e := os.Mkdir(dir, 0700); e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(dir, "accounts.journal")
	journal, e := operatorauth.CreateAccountJournal(path, operatorauth.AccountSnapshot{AuthorityID: authority, Profile: "tls", Version: operatorauth.AccountVersion, Revision: 1, Accounts: records})
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = journal.Close() }()
	openManager := func() *operatorauth.Manager {
		m, e := operatorauth.New(operatorauth.Config{AuthorityID: authority, AuthorityProfile: "tls", AuthorityStore: journal})
		if e != nil {
			t.Fatal(e)
		}
		return m
	}
	auth := openManager()
	login := func(name string) operatorauth.Session {
		s, e := auth.LoginNamed(ctx, "127.0.0.1", name, password)
		if e != nil {
			t.Fatal(e)
		}
		return s
	}
	admin, worker, other := login("admin"), login("worker"), login("other")
	// Separate enrolled devices retain an unconsumed old job and an unrelated
	// actor's job while the first device's permit is in flight.
	claims := make([]func() ([]byte, func(), error), 3)
	for i, s := range []operatorauth.Session{worker, worker, other} {
		h := serviceAccountHarness(t, false)
		if e := h.configure(func(c context.Context, a string, epoch uint64, caps ...operatorauth.Capability) (context.Context, func(), error) {
			return auth.LeaseActor(c, a, epoch, caps...)
		}); e != nil {
			t.Fatal(e)
		}
		var epoch uint64
		claims[i], epoch = h.approve(operatorauth.WithApprovalEpoch(ctx, s.ApprovalEpoch()), s.ActorID())
		if epoch != s.ApprovalEpoch() {
			t.Fatal("approval epoch not persisted")
		}
	}
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	wrapped := &serviceJournalListener{Listener: listener, accepted: make(chan *serviceJournalSocket, 1)}
	handlerDone := make(chan struct{})
	claimErr := make(chan error, 1)
	payload := make(chan []byte, 1)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer close(handlerDone)
		raw, release, err := claims[0]()
		if err != nil {
			claimErr <- err
			http.Error(w, "denied", 403)
			return
		}
		defer release()
		payload <- bytes.Clone(raw)
		if err = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second)); err != nil {
			claimErr <- err
			return
		}
		writeAccountBoundJSONResponse(w, r, raw, true)
	})}
	serveDone := make(chan struct{})
	go func() { _ = server.Serve(wrapped); close(serveDone) }()
	t.Cleanup(func() { _ = server.Close(); <-serveDone })
	client, e := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
	if e != nil {
		t.Fatal(e)
	}
	defer client.Close()
	if e = client.SetDeadline(time.Now().Add(5 * time.Second)); e != nil {
		t.Fatal(e)
	}
	if _, e = io.WriteString(client, "GET / HTTP/1.1\r\nHost: fixture\r\nConnection: close\r\n\r\n"); e != nil {
		t.Fatal(e)
	}
	var socket *serviceJournalSocket
	select {
	case socket = <-wrapped.accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("socket not accepted")
	}
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(socket.resume) }) })
	select {
	case <-socket.entered:
	case err := <-claimErr:
		t.Fatal(err)
	case <-time.After(5 * time.Second):
		t.Fatal("permit never reached socket")
	}
	changed := make(chan error, 1)
	go func() {
		changed <- auth.ChangeAccount(ctx, admin, operatorauth.AccountChange{TargetID: workerID, ExpectedRevision: 1, Disabled: true, Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.RestartService}})
	}()
	select {
	case <-worker.Lifetime().Done():
	case <-time.After(5 * time.Second):
		t.Fatal("target session not cancelled during drain")
	}
	if _, err := auth.Lookup(worker.Token); err == nil {
		t.Fatal("target cookie remains valid")
	}
	if _, release, err := auth.LeaseActor(ctx, workerID, 1, operatorauth.RestartService); err == nil {
		release()
		t.Fatal("target still admits")
	}
	if _, err := auth.Lookup(other.Token); err != nil {
		t.Fatal("unrelated session blocked during withdrawal", err)
	}
	_, otherRelease, err := auth.LeaseActor(ctx, otherID, 1, operatorauth.RestartService)
	if err != nil {
		t.Fatal("unrelated authority blocked during withdrawal", err)
	}
	otherRelease()
	select {
	case err := <-changed:
		t.Fatalf("change returned before socket release: %v", err)
	default:
	}
	// Revoke-before-claim yields no permit/body eligible for an authorized write.
	if raw, release, err := claims[1](); err == nil || len(raw) != 0 || release != nil {
		if release != nil {
			release()
		}
		t.Fatal("revoked claim released permit")
	}
	unblock.Do(func() { close(socket.resume) })
	response, e := http.ReadResponse(bufio.NewReader(client), nil)
	if e != nil {
		t.Fatal(e)
	}
	received, e := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(received, <-payload) {
		t.Fatal("actual permit bytes changed in response")
	}
	select {
	case <-handlerDone:
	case <-time.After(5 * time.Second):
		t.Fatal("response lease did not release")
	}
	select {
	case e := <-changed:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("revocation failed to drain")
	}
	if e = auth.ChangeAccount(ctx, admin, operatorauth.AccountChange{TargetID: workerID, ExpectedRevision: 2, Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.RestartService}}); e != nil {
		t.Fatal(e)
	}
	if e = journal.Close(); e != nil {
		t.Fatal(e)
	}
	journal, e = operatorauth.OpenAccountJournal(path)
	if e != nil {
		t.Fatal(e)
	}
	auth = openManager() // old manager's goroutines have drained
	fresh := login("worker")
	if fresh.ApprovalEpoch() != 3 {
		t.Fatal("journal lost account revision")
	}
	if raw, release, err := claims[1](); err == nil || len(raw) != 0 || release != nil {
		if release != nil {
			release()
		}
		t.Fatal("restart/regrant revived old approval")
	}
	other = login("other")
	if other.ApprovalEpoch() != 1 {
		t.Fatal("unrelated account changed")
	}
	raw, release, e := claims[2]()
	if e != nil || len(raw) == 0 || release == nil {
		t.Fatal("other actor blocked", e)
	}
	release()
}
