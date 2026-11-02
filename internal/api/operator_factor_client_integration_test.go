//go:build linux

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"localrmm/internal/lanconfig"
	"localrmm/internal/lanstore"
	"localrmm/internal/operatorauth"
	"localrmm/internal/operatorfactorclient"
	"localrmm/internal/operatorfactorcustody"
)

func factorClientTarget(t *testing.T, client *operatorfactorclient.Client, id string, revision uint64) operatorfactorclient.Account {
	t.Helper()
	accounts, err := client.Accounts(context.Background())
	if err != nil {
		t.Fatal("read actual account review", operatorfactorclient.Code(err))
	}
	for _, account := range accounts {
		if account.ID == id {
			if account.Revision != revision || account.Uncertain || account.Disabled {
				t.Fatal("actual account review did not match expected authority")
			}
			return account
		}
	}
	t.Fatal("actual review omitted the selected account")
	return operatorfactorclient.Account{}
}

// The test's software authenticator reads only its synthetic private handoff.
// The shipped command never computes a proof from manager-side secret custody.
func factorClientHandoff(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("read synthetic authenticator handoff", err)
	}
	defer clear(raw)
	var handoff struct {
		Secret string `json:"secret"`
	}
	if json.Unmarshal(raw, &handoff) != nil || len(handoff.Secret) != 52 {
		t.Fatal("invalid private authenticator handoff")
	}
	return handoff.Secret
}

func TestFactorClientRealTLSCustodyEnrollmentResetAndReopen(t *testing.T) {
	ctx := context.Background()
	const otherID = "operator_00000000000000000000000000000003"
	clock := &factorAPIClock{now: time.Now().UTC()}
	root := filepath.Join(t.TempDir(), "private")
	state, material, handoffs, web := filepath.Join(root, "state"), filepath.Join(root, "material"), filepath.Join(root, "handoffs"), filepath.Join(root, "web")
	for _, dir := range []string{root, state, material, handoffs, web} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := lanstore.PrepareProfileDirectory(state, "tls"); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(state, lanconfig.AccountAuthorityJournalFile)
	initial := operatorauth.AccountSnapshot{Version: operatorauth.AccountVersion, AuthorityID: lifecycleAuthorityID, Profile: "tls", Revision: 1, Accounts: []operatorauth.AccountRecord{
		{Operator: operatorauth.Operator{ID: lifecycleAdminID, Username: "admin", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.ManageAccounts}}, Revision: 1},
		{Operator: operatorauth.Operator{ID: lifecycleWorkerID, Username: "worker", PasswordHash: lifecyclePasswordHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.RestartService}}, Revision: 1},
		{Operator: operatorauth.Operator{ID: otherID, Username: "other-admin", PasswordHash: testOperatorHash(), Capabilities: []operatorauth.Capability{operatorauth.Read, operatorauth.ManageAccounts}}, Revision: 1},
	}}
	journal, err := operatorauth.CreateAccountJournal(journalPath, initial)
	if err != nil {
		t.Fatal("real protected authority", err)
	}
	defer func() { _ = journal.Close() }()
	newAuth := func(j *operatorauth.AccountJournal) *operatorauth.Manager {
		t.Helper()
		auth, err := operatorauth.New(operatorauth.Config{AuthorityID: lifecycleAuthorityID, AuthorityProfile: "tls", AuthorityStore: j, Now: clock.Now})
		if err != nil {
			t.Fatal(err)
		}
		return auth
	}
	auth := newAuth(journal)
	server := newOperatorFixtureWithAuth(t, auth)
	server.app.web = web
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.server.Certificate().Raw})
	certificatePath, referencePath := filepath.Join(material, "server.pem"), filepath.Join(material, "auth.json")
	writeJSON := func(path string, value any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(raw)
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(certificatePath, certificate, 0644); err != nil {
		t.Fatal(err)
	}
	reference := lanconfig.AccountAuthorityReference{SchemaVersion: lanconfig.AccountAuthorityVersion, Profile: "tls", AuthorityID: lifecycleAuthorityID, AuthorityFile: journalPath}
	writeJSON(referencePath, reference)
	marker, err := lanconfig.AccountAuthorityMarkerBytes(state, reference)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, lanconfig.AccountAuthorityMarkerFile), marker, 0600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(material, "lan.json")
	config := lanconfig.Config{SchemaVersion: lanconfig.SchemaVersion, Profile: "tls", OperatorListen: server.server.Listener.Addr().String(), AgentListen: "127.0.0.1:20001", OperatorOrigin: server.server.URL, AgentOrigin: "https://127.0.0.1:20001", TLSCertificateFile: certificatePath, TLSPrivateKeyFile: filepath.Join(material, "must-not-be-read.key"), AgentClientCAFile: filepath.Join(material, "unused-agent-ca.pem"), OperatorAuthFile: referencePath, StateDirectory: state, WebDirectory: web}
	writeJSON(configPath, config)
	newClient := func(origin string, certificate []byte) *operatorfactorclient.Client {
		t.Helper()
		client, err := operatorfactorclient.New(operatorfactorclient.Config{Origin: origin, ServerCertificate: certificate})
		if err != nil {
			t.Fatal("pinned client", operatorfactorclient.Code(err))
		}
		t.Cleanup(client.Close)
		return client
	}
	login := func(client *operatorfactorclient.Client, user, password, secret string) {
		t.Helper()
		var otp []byte
		if secret != "" {
			otp = []byte(factorAPICode(t, secret, clock.Now()))
		}
		defer clear(otp)
		if err := client.Login(ctx, user, []byte(password), otp); err != nil {
			t.Fatal("actual client login", operatorfactorclient.Code(err))
		}
	}
	bootstrap := newClient(server.server.URL, certificate)
	if err := bootstrap.Check(ctx); err != nil {
		t.Fatal("profile preflight", operatorfactorclient.Code(err))
	}
	login(bootstrap, "admin", operatorFixturePassword, "")
	stage := func(client *operatorfactorclient.Client, id string, revision uint64, file string, replace bool) string {
		t.Helper()
		target := factorClientTarget(t, client, id, revision)
		plan, err := operatorfactorcustody.PlanFor(operatorfactorcustody.Options{LanConfig: configPath, RuntimeUID: os.Geteuid(), ActorID: id, ExpectedRevision: revision, HandoffFile: file, Acknowledge: true, ReplaceStale: replace})
		if err != nil {
			t.Fatal("real custody plan", operatorfactorcustody.Code(err))
		}
		before, _ := journal.Load(ctx)
		result, err := plan.Stage(ctx, target)
		if err != nil || !result.ProposalCreated || !result.HandoffCreated || result.Archived != replace {
			t.Fatal("real custody staging", operatorfactorcustody.Code(err))
		}
		after, _ := journal.Load(ctx)
		if after.Revision != before.Revision {
			t.Fatal("custody staging changed live authority")
		}
		if _, err := os.Stat(config.TLSPrivateKeyFile); !os.IsNotExist(err) {
			t.Fatal("custody required or created a server private key")
		}
		return factorClientHandoff(t, file)
	}
	adminSecret := stage(bootstrap, lifecycleAdminID, 1, filepath.Join(handoffs, "admin.json"), false)
	workerSecret := stage(bootstrap, lifecycleWorkerID, 1, filepath.Join(handoffs, "worker.json"), false)
	oldProposalPath := journalPath + ".factor-" + lifecycleWorkerID + ".json"
	oldProposal, err := os.ReadFile(oldProposalPath)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(oldProposal)
	enroll := func(user, password, secret string, revision uint64) {
		t.Helper()
		client := newClient(server.server.URL, certificate)
		if err := client.Enroll(ctx, user, []byte(password), []byte(factorAPICode(t, secret, clock.Now())), revision); err != nil {
			t.Fatal("actual client enrollment", operatorfactorclient.Code(err))
		}
		if client.ActorID() != "" {
			t.Fatal("enrollment created a client session")
		}
	}
	enroll("admin", operatorFixturePassword, adminSecret, 1)
	enroll("worker", lifecycleNewPassword, workerSecret, 1)
	if err := bootstrap.Logout(ctx); err != nil {
		t.Fatal("already-revoked bootstrap cleanup", operatorfactorclient.Code(err))
	}
	clock.Advance()
	admin, worker, other := newClient(server.server.URL, certificate), newClient(server.server.URL, certificate), newClient(server.server.URL, certificate)
	login(admin, "admin", operatorFixturePassword, adminSecret)
	login(worker, "worker", lifecycleNewPassword, workerSecret)
	login(other, "other-admin", operatorFixturePassword, "")
	if worker.CanManageAccounts() || !admin.CanManageAccounts() || worker.ActorID() != lifecycleWorkerID {
		t.Fatal("client invented authority or lost actual requester")
	}
	clock.Advance()
	if err := admin.Reset(ctx, lifecycleWorkerID, 2, []byte(operatorFixturePassword), []byte(factorAPICode(t, adminSecret, clock.Now()))); err != nil {
		t.Fatal("actual fresh requester reset", operatorfactorclient.Code(err))
	}
	if err := worker.Logout(ctx); err != nil {
		t.Fatal("revoked target cleanup", operatorfactorclient.Code(err))
	}
	for _, otp := range [][]byte{nil, []byte(factorAPICode(t, workerSecret, clock.Now()))} {
		if err := worker.Login(ctx, "worker", []byte(lifecycleNewPassword), otp); !errors.Is(err, operatorfactorclient.ErrUnauthenticated) {
			t.Fatal("pending factor allowed password/old factor", operatorfactorclient.Code(err))
		}
	}
	if release, err := auth.BeginActorAdmission(ctx, lifecycleWorkerID, 2, operatorauth.RestartService); err == nil {
		release()
		t.Fatal("actual client reset revived old approval authority")
	}
	newSecret := stage(other, lifecycleWorkerID, 3, filepath.Join(handoffs, "worker-new.json"), true)
	archive, err := os.ReadFile(oldProposalPath + ".retired-1")
	if err != nil || !bytes.Equal(archive, oldProposal) {
		t.Fatal("explicit stale replacement did not preserve previous custody bytes")
	}
	clear(archive)
	enroll("worker", lifecycleNewPassword, newSecret, 3)
	clock.Advance()
	login(worker, "worker", lifecycleNewPassword, newSecret)
	if _, err := admin.Accounts(ctx); err != nil {
		t.Fatal("reset withdrew independent administrator", operatorfactorclient.Code(err))
	}
	if _, err := other.Accounts(ctx); err != nil {
		t.Fatal("custody withdrew the other administrator", operatorfactorclient.Code(err))
	}
	if err := worker.Logout(ctx); err != nil {
		t.Fatal("confirmed target logout", operatorfactorclient.Code(err))
	}
	if err := admin.Logout(ctx); err != nil {
		t.Fatal("confirmed requester logout", operatorfactorclient.Code(err))
	}
	if err := other.Logout(ctx); err != nil {
		t.Fatal("confirmed independent-admin logout", operatorfactorclient.Code(err))
	}
	if err := journal.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := operatorauth.OpenAccountJournal(journalPath)
	if err != nil {
		t.Fatal("real authority reopen", err)
	}
	defer reopened.Close()
	restarted := newOperatorFixtureWithAuth(t, newAuth(reopened))
	restartedCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: restarted.server.Certificate().Raw})
	freshClient := newClient(restarted.server.URL, restartedCert)
	if err := freshClient.Login(ctx, "worker", []byte(lifecycleNewPassword), []byte(factorAPICode(t, newSecret, clock.Now()))); !errors.Is(err, operatorfactorclient.ErrUnauthenticated) {
		t.Fatal("restarted actual client replayed an already consumed OTP", operatorfactorclient.Code(err))
	}
	clock.Advance()
	login(freshClient, "worker", lifecycleNewPassword, newSecret)
	if err := freshClient.Logout(ctx); err != nil {
		t.Fatal("restarted client cleanup", operatorfactorclient.Code(err))
	}
}

func TestFactorClientLoginAuthorityUncertaintyIsNotCredentials(t *testing.T) {
	ctx := context.Background()
	journal, path, initial := lifecycleJournal(t)
	secret := factorAPISecret(t)
	factorAPIProposal(t, path, lifecycleWorkerID, secret, 1)
	if err := initial.EnrollFactor(ctx, "127.0.0.1", "worker", operatorFixturePassword, factorAPICode(t, secret, time.Now()), 1); err != nil {
		t.Fatal("prepare real enrolled factor", err)
	}
	now := time.Now().Add(61 * time.Second)
	auth, err := operatorauth.New(operatorauth.Config{AuthorityID: lifecycleAuthorityID, AuthorityProfile: "tls", AuthorityStore: journal, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	fixture := newOperatorFixtureWithAuth(t, auth)
	client, err := operatorfactorclient.New(operatorfactorclient.Config{Origin: fixture.server.URL, ServerCertificate: fixture.server.Certificate().Raw})
	if err != nil {
		t.Fatal("pinned protocol client", operatorfactorclient.Code(err))
	}
	defer client.Close()
	// Only this newly created fixture journal is changed. A later real OTP
	// consume must observe actual file-size uncertainty, not a mocked HTTP error.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.Write([]byte{'\n'}); err != nil {
		f.Close()
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	err = client.Login(ctx, "worker", []byte(operatorFixturePassword), []byte(factorAPICode(t, secret, now)))
	if !errors.Is(err, operatorfactorclient.ErrUncertain) {
		t.Fatal("durable OTP uncertainty was reported as ordinary credential failure", operatorfactorclient.Code(err))
	}
	if client.ActorID() != "" || auth.ActorHasCapability(lifecycleWorkerID, operatorauth.RestartService) {
		t.Fatal("uncertain OTP consumption retained authentication or dispatch authority")
	}
	if _, err := auth.LoginNamed(ctx, "127.0.0.2", "admin", operatorFixturePassword); err != nil {
		t.Fatal("unrelated factorless administrator was fenced", err)
	}
}
