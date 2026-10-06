package enrollmentstore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"localrmm/internal/actionpermit"
	"localrmm/internal/enrollmentstate"
)

func setupFixture(t *testing.T) (fixture, *Store, string, enrollmentstate.Snapshot, ed25519.PublicKey, time.Time) {
	t.Helper()
	f, s, path, snap, _, at := journalFixture(t)
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{81}, 32)).Public().(ed25519.PublicKey)
	return f, s, path, snap, key, at
}
func credentialBytes(t *testing.T, s *Store, id string) []byte {
	t.Helper()
	var body []byte
	if err := s.db.QueryRow(`SELECT body FROM enrollment_credentials WHERE invitation_id=?`, id).Scan(&body); err != nil {
		t.Fatal(err)
	}
	return body
}
func setupDomain(t *testing.T, s *Store, snap enrollmentstate.Snapshot, key ed25519.PublicKey, at time.Time) {
	t.Helper()
	if err := s.SetupServiceActionsCreateOnly(context.Background(), key, snap.Approval.DeviceID, "sha256:"+snap.Issuance.CertificateHash, at); err != nil {
		t.Fatal(err)
	}
}
func TestServiceActionSetupLegacyCanonicalBytesUnchanged(t *testing.T) {
	_, s, _, snap, key, at := setupFixture(t)
	before := credentialBytes(t, s, snap.InvitationID)
	var current credential
	if json.Unmarshal(before, &current) != nil || current.ServiceActionSetup != nil {
		t.Fatal("unexpected setup marker")
	}
	// Keep the old four-field contract explicit rather than comparing two
	// encodings through the newly extended type.
	legacy, err := json.Marshal(struct {
		DER      []byte   `json:"der"`
		Delivery Delivery `json:"delivery"`
		Replay   Replay   `json:"replay"`
		Frame    []byte   `json:"frame"`
	}{current.DER, current.Delivery, current.Replay, current.Frame})
	if err != nil || !bytes.Equal(before, legacy) {
		t.Fatal("legacy credential serialization changed")
	}
	if err = s.InitializeServiceActions(context.Background(), key); err != nil {
		t.Fatal(err)
	}
	if err = s.InitializeServiceActionIdentity(context.Background(), key, snap.Approval.DeviceID, at); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, credentialBytes(t, s, snap.InvitationID)) {
		t.Fatal("legacy initialization rewrote credential")
	}
}
func TestServiceActionSetupCreateOnlyAtomicAndRuntime(t *testing.T) {
	f, s, path, snap, key, at := setupFixture(t)
	ctx := context.Background()
	before := credentialBytes(t, s, snap.InvitationID)
	setupDomain(t, s, snap, key, at)
	body := credentialBytes(t, s, snap.InvitationID)
	var c credential
	if json.Unmarshal(body, &c) != nil || c.ServiceActionSetup == nil || !validServiceActionSetupMarker(snap, c.ServiceActionSetup) {
		t.Fatal("missing valid credential fence")
	}
	if bytes.Equal(before, body) {
		t.Fatal("marker not persisted")
	}
	var digest string
	if s.db.QueryRow(`SELECT setup_fence FROM enrollment_service_action_records WHERE invitation_id=?`, snap.InvitationID).Scan(&digest) != nil || digest != c.ServiceActionSetup.digest() {
		t.Fatal("row marker digest differs")
	}
	if err := s.SetupServiceActionsCreateOnly(ctx, key, snap.Approval.DeviceID, "sha256:"+snap.Issuance.CertificateHash, at); !errors.Is(err, enrollmentstate.ErrConflict) {
		t.Fatal("setup retry adopted existing domain", err)
	}
	other := f.open(t, path)
	if err := other.OpenServiceActions(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := other.ServiceActionView(ctx, key, snap.Approval.DeviceID, at); err != nil {
		t.Fatal("fenced runtime view failed", err)
	}
	if !bytes.Equal(body, credentialBytes(t, s, snap.InvitationID)) {
		t.Fatal("runtime changed immutable setup marker")
	}
	inspection, err := inspectServiceActionsInProcess(t, ctx, path, f.issuerDER, snap.Approval.DeviceID, at)
	if err != nil || inspection.Status != ServiceActionSetupFenced || inspection.Config != f.config || inspection.Identity != snap || !bytes.Equal(inspection.PublicKey, key) {
		t.Fatal("fenced inspection", err)
	}
}
func TestServiceActionSetupLegacyDomainNotAdopted(t *testing.T) {
	f, s, path, snap, private, at := actionFixture(t)
	key := private.Public().(ed25519.PublicKey)
	inspection, err := inspectServiceActionsInProcess(t, context.Background(), path, f.issuerDER, snap.Approval.DeviceID, at)
	if err != nil || inspection.Status != ServiceActionSetupLegacy {
		t.Fatal("legacy runtime no longer supported", err)
	}
	before := credentialBytes(t, s, snap.InvitationID)
	if err := s.SetupServiceActionsCreateOnly(context.Background(), key, snap.Approval.DeviceID, "sha256:"+snap.Issuance.CertificateHash, at); !errors.Is(err, enrollmentstate.ErrConflict) {
		t.Fatal("legacy domain adopted", err)
	}
	if !bytes.Equal(before, credentialBytes(t, s, snap.InvitationID)) {
		t.Fatal("legacy refusal rewrote credential")
	}
}
func TestServiceActionSetupRejectsMissingAndMismatchedFence(t *testing.T) {
	for _, corruption := range []string{"row", "meta", "schema", "marker", "marker-key", "row-fence", "public-key"} {
		t.Run(corruption, func(t *testing.T) {
			f, s, path, snap, key, at := setupFixture(t)
			setupDomain(t, s, snap, key, at)
			var err error
			switch corruption {
			case "row":
				_, err = s.db.Exec(`DELETE FROM enrollment_service_action_records`)
			case "meta":
				_, err = s.db.Exec(`DELETE FROM enrollment_service_action_meta`)
			case "schema":
				_, err = s.db.Exec(`DROP TABLE enrollment_service_action_records; DROP TABLE enrollment_service_action_meta`)
			case "marker", "marker-key":
				var c credential
				json.Unmarshal(credentialBytes(t, s, snap.InvitationID), &c)
				if corruption == "marker" {
					c.ServiceActionSetup = nil
				} else {
					c.ServiceActionSetup.KeyID = actionpermit.Digest([]byte("different key"))
				}
				body, _ := json.Marshal(c)
				_, err = s.db.Exec(`UPDATE enrollment_credentials SET body=? WHERE invitation_id=?`, body, snap.InvitationID)
			case "row-fence":
				_, err = s.db.Exec(`UPDATE enrollment_service_action_records SET setup_fence=?`, actionpermit.Digest([]byte("other fence")))
			case "public-key":
				other := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{82}, 32)).Public().(ed25519.PublicKey)
				_, err = s.db.Exec(`UPDATE enrollment_service_action_meta SET public_key=?`, []byte(other))
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = s.SetupServiceActionsCreateOnly(context.Background(), key, snap.Approval.DeviceID, "sha256:"+snap.Issuance.CertificateHash, at); err == nil {
				t.Fatal("setup accepted partial used state")
			}
			if err = s.InitializeServiceActions(context.Background(), key); err == nil {
				t.Fatal("legacy initializer repaired partial used state")
			}
			if err = s.InitializeServiceActionIdentity(context.Background(), key, snap.Approval.DeviceID, at); err == nil {
				t.Fatal("legacy identity initializer repaired partial used state")
			}
			if _, err = inspectServiceActionsInProcess(t, context.Background(), path, f.issuerDER, snap.Approval.DeviceID, at); err == nil {
				t.Fatal("inspection accepted partial used state")
			}
			if reopened, err := Open(path, f.config, f.issuerDER); err == nil {
				reopened.Close()
				t.Fatal("runtime reopened partial used state")
			}
		})
	}
}
func TestServiceActionSetupInterruptedTransactionLeavesNoArtifacts(t *testing.T) {
	for _, cancel := range []bool{false, true} {
		t.Run(map[bool]string{false: "error", true: "canceled"}[cancel], func(t *testing.T) {
			f, s, path, snap, key, at := setupFixture(t)
			before := credentialBytes(t, s, snap.InvitationID)
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			err := s.transact(ctx, func(tx *transaction) error {
				if err := s.setupServiceActionsCreateOnly(ctx, tx, key, snap.Approval.DeviceID, "sha256:"+snap.Issuance.CertificateHash, at); err != nil {
					return err
				}
				if cancel {
					stop()
					return nil
				}
				return errors.New("fixture interruption before commit")
			})
			if err == nil || !bytes.Equal(before, credentialBytes(t, s, snap.InvitationID)) {
				t.Fatal("interrupted credential marker persisted", err)
			}
			var count int
			if s.db.QueryRow(`SELECT count(*) FROM sqlite_master WHERE name LIKE 'enrollment_service_action_%'`).Scan(&count) != nil || count != 0 {
				t.Fatal("interrupted action schema persisted")
			}
			inspection, err := inspectServiceActionsInProcess(t, context.Background(), path, f.issuerDER, snap.Approval.DeviceID, at)
			if err != nil || inspection.Status != ServiceActionSetupAbsent {
				t.Fatal("interrupted transaction left partial domain", err)
			}
			setupDomain(t, s, snap, key, at)
		})
	}
}
func TestServiceActionSetupConcurrentCreateOnlyOneCommit(t *testing.T) {
	f, s, path, snap, key, at := setupFixture(t)
	other := f.open(t, path)
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, store := range []*Store{s, other} {
		wg.Add(1)
		go func(store *Store) {
			defer wg.Done()
			results <- store.SetupServiceActionsCreateOnly(context.Background(), key, snap.Approval.DeviceID, "sha256:"+snap.Issuance.CertificateHash, at)
		}(store)
	}
	wg.Wait()
	close(results)
	var committed, refused int
	for err := range results {
		if err == nil {
			committed++
		} else if errors.Is(err, enrollmentstate.ErrConflict) {
			refused++
		} else {
			t.Fatal(err)
		}
	}
	if committed != 1 || refused != 1 {
		t.Fatal("concurrent setup commits", committed, refused)
	}
}
func directoryContents(t *testing.T, dir string) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, entry := range entries {
		body, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[entry.Name()] = body
	}
	return out
}
func TestServiceActionSetupInspectionReadOnlyLiveAndClosed(t *testing.T) {
	for _, closed := range []bool{false, true} {
		t.Run(map[bool]string{false: "live-wal", true: "closed-no-wal"}[closed], func(t *testing.T) {
			f, s, path, snap, _, at := setupFixture(t)
			if closed {
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
			}
			before := directoryContents(t, filepath.Dir(path))
			inspection, err := inspectServiceActionsInProcess(t, context.Background(), path, f.issuerDER, snap.Approval.DeviceID, at)
			if err != nil || inspection.Status != ServiceActionSetupAbsent || inspection.Config != f.config || inspection.Identity != snap || inspection.PublicKey != nil {
				t.Fatal("read-only inspection", err)
			}
			after := directoryContents(t, filepath.Dir(path))
			if !reflect.DeepEqual(before, after) {

				t.Fatal("inspection created or changed database files/sidecars")
			}
		})
	}
}
func TestServiceActionSetupInspectionRefusesMissingAndPartialPaths(t *testing.T) {
	f, s, path, snap, _, at := setupFixture(t)
	t.Run("missing-database", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "missing", "enrollment.sqlite")
		if _, err := inspectServiceActionsInProcess(t, context.Background(), missing, f.issuerDER, snap.Approval.DeviceID, at); err == nil {
			t.Fatal("missing database accepted")
		}
		if _, err := os.Stat(filepath.Dir(missing)); !os.IsNotExist(err) {
			t.Fatal("inspection created directory")
		}
	})
	t.Run("live-wal-without-shm", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "private")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		copyPath := filepath.Join(dir, "enrollment.sqlite")
		for _, suffix := range []string{"", "-wal"} {
			body, err := os.ReadFile(path + suffix)
			if err != nil || os.WriteFile(copyPath+suffix, body, 0600) != nil {
				t.Fatal("fixture copy", err)
			}
		}
		before := directoryContents(t, dir)
		if _, err := inspectServiceActionsInProcess(t, context.Background(), copyPath, f.issuerDER, snap.Approval.DeviceID, at); err == nil {
			t.Fatal("missing shared index accepted")
		}
		if !reflect.DeepEqual(before, directoryContents(t, dir)) {
			t.Fatal("inspection repaired missing shared index")
		}
	})
	if err := s.SetupServiceActionsCreateOnly(context.Background(), ed25519.NewKeyFromSeed(bytes.Repeat([]byte{83}, 32)).Public().(ed25519.PublicKey), snap.Approval.DeviceID, "sha256:"+strings.Repeat("a", 64), at); !errors.Is(err, enrollmentstate.ErrProof) {
		t.Fatal("wrong incarnation accepted", err)
	}
}

// The production planner and running manager are separate processes. This
// fixture exercises SQLite's real read-only WAL-index path without reusing a
// writable index that another Store opened in this test process.
func inspectServiceActionsInProcess(t *testing.T, ctx context.Context, path string, issuer []byte, device string, now time.Time) (ServiceActionSetupInspection, error) {
	t.Helper()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestServiceActionSetupReadOnlyProcess$")
	cmd.Env = append(os.Environ(), "TRACEBOLT_SETUP_INSPECT_PATH="+path, "TRACEBOLT_SETUP_INSPECT_ISSUER="+base64.RawStdEncoding.EncodeToString(issuer), "TRACEBOLT_SETUP_INSPECT_DEVICE="+device, "TRACEBOLT_SETUP_INSPECT_NOW="+now.Format(time.RFC3339Nano))
	body, err := cmd.Output()
	if err != nil {
		t.Fatal("read-only inspection subprocess", err)
	}
	var out struct {
		Inspection ServiceActionSetupInspection
		Error      string
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal("inspection subprocess response", err)
	}
	if out.Error != "" {
		return ServiceActionSetupInspection{}, errors.New(out.Error)
	}
	return out.Inspection, nil
}
func TestServiceActionSetupReadOnlyProcess(t *testing.T) {
	path := os.Getenv("TRACEBOLT_SETUP_INSPECT_PATH")
	if path == "" {
		t.Skip("inspection subprocess fixture only")
	}
	issuer, err := base64.RawStdEncoding.DecodeString(os.Getenv("TRACEBOLT_SETUP_INSPECT_ISSUER"))
	if err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339Nano, os.Getenv("TRACEBOLT_SETUP_INSPECT_NOW"))
	if err != nil {
		t.Fatal(err)
	}
	inspection, err := InspectServiceActionSetup(context.Background(), path, issuer, os.Getenv("TRACEBOLT_SETUP_INSPECT_DEVICE"), now)
	out := struct {
		Inspection ServiceActionSetupInspection
		Error      string
	}{Inspection: inspection}
	if err != nil {
		out.Error = err.Error()
	}
	if json.NewEncoder(os.Stdout).Encode(out) != nil {
		os.Exit(2)
	}
	os.Exit(0)
}
func TestServiceActionSetupInspectionRefusesSharedWritableMapping(t *testing.T) {
	f, _, path, snap, _, at := setupFixture(t)
	before := directoryContents(t, filepath.Dir(path))
	if _, err := InspectServiceActionSetup(context.Background(), path, f.issuerDER, snap.Approval.DeviceID, at); !errors.Is(err, ErrServiceActionInspectionBusy) {
		t.Fatal("inspection reused writable process WAL index", err)
	}
	if !reflect.DeepEqual(before, directoryContents(t, filepath.Dir(path))) {
		t.Fatal("blocked inspection changed files")
	}
}

func TestServiceActionSetupMarkerImmutableWithinTransaction(t *testing.T) {
	_, s, _, snap, key, at := setupFixture(t)
	setupDomain(t, s, snap, key, at)
	before := credentialBytes(t, s, snap.InvitationID)
	for _, remove := range []bool{false, true} {
		err := s.transact(context.Background(), func(tx *transaction) error {
			c := tx.credentials[snap.InvitationID]
			if remove {
				c.ServiceActionSetup = nil
			} else {
				c.ServiceActionSetup.InitializedAt = c.ServiceActionSetup.InitializedAt.Add(time.Second)
			}
			tx.credentials[snap.InvitationID] = c
			return nil
		})
		if err == nil || !bytes.Equal(before, credentialBytes(t, s, snap.InvitationID)) {
			t.Fatal("immutable setup marker changed", err)
		}
	}
}
