package enrollmentstore

import (
	"context"
	"errors"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"path/filepath"
	"testing"
)

func TestSelfClaimAtomicPendingAndRestart(t *testing.T) {
	f := newFixture(t)
	f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory
	f.challenge.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory
	path := filepath.Join(t.TempDir(), "private", "self.db")
	s := f.open(t, path)
	proof := f.claim(t)
	pending, err := s.SelfClaim(context.Background(), proof, testNow+1)
	if err != nil || pending.State != enrollmentstate.ClaimedPending || pending.Approval.DeviceID != "" || !IsSelfRegistration(pending) {
		t.Fatal("self claim must only create pending identity", err)
	}
	retry, err := s.SelfClaim(context.Background(), proof, testNow+2)
	if err != nil || retry != pending {
		t.Fatal("exact retry changed identity", err)
	}
	if _, err := s.SelfClaim(context.Background(), enrollmentcrypto.VerifiedClaim{}, testNow+2); err == nil {
		t.Fatal("unverified claim accepted")
	}
	s.Close()
	s = f.open(t, path)
	retry, err = s.SelfClaim(context.Background(), proof, testNow+3)
	if err != nil || retry != pending {
		t.Fatal("restart lost pending identity", err)
	}
	approved, err := s.Approve(context.Background(), enrollmentstate.ApproveCommand{Control: control(pending, 10), DeviceID: id("agent", 1), KeyFingerprint: pending.Claim.KeyFingerprint})
	if err != nil || approved.State != enrollmentstate.Approved {
		t.Fatal("operator approval required and preserved", err)
	}
	if _, err := s.SelfClaim(context.Background(), proof, testNow+4); !errors.Is(err, enrollmentstate.ErrState) {
		t.Fatal("self claim must not reset an approved identity", err)
	}
}

func TestSelfClaimFailureRollsBackCreation(t *testing.T) {
	f := newFixture(t)
	f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory
	f.challenge.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory
	f.challenge.ManagerInstanceID = id("manager", 2)
	s := f.open(t, filepath.Join(t.TempDir(), "private", "self.db"))
	if _, err := s.SelfClaim(context.Background(), f.claim(t), testNow+1); err == nil {
		t.Fatal("foreign binding accepted")
	}
	rows, err := s.Snapshots(context.Background())
	if err != nil || len(rows) != 0 {
		t.Fatal("failed claim persisted partial creation", err)
	}
}

func TestSelfClaimCannotAdoptInvitationOrOtherProfile(t *testing.T) {
	f, s, _ := fixtureStore(t)
	if _, err := s.SelfClaim(context.Background(), f.claim(t), testNow+1); err != nil {
		t.Fatal("legacy Linux domain rejected self registration", err)
	}
	f.config.Binding.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory
	f.challenge.CollectionProfile = enrollmentcrypto.CollectionProfileWindowsInventory
	s = f.open(t, filepath.Join(t.TempDir(), "private", "windows.db"))
	create := f.createCommand()
	create.Platform = "windows"
	if _, err := s.CreateInvitation(context.Background(), create); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SelfClaim(context.Background(), f.claim(t), testNow+1); !errors.Is(err, enrollmentstate.ErrConflict) {
		t.Fatal("ordinary invitation adopted", err)
	}
}

func TestSelfRegistrationPlatformFence(t *testing.T) {
	for _, tc := range []struct {
		platform, profile, transport, want string
		renewal                            bool
	}{
		{"", enrollmentcrypto.CollectionProfile, "tls", "linux", false},
		{"", enrollmentcrypto.CollectionProfileMacOSInventory, "tls", "", false},
		{"darwin", enrollmentcrypto.CollectionProfileMacOSInventory, "tls", "darwin", false},
		{"darwin", enrollmentcrypto.CollectionProfileOperational, "tls", "", false},
		{"linux", enrollmentcrypto.CollectionProfileWindowsInventory, "tls", "", false},
		{"linux", enrollmentcrypto.CollectionProfile, "http-test", "", false},
		{"linux", enrollmentcrypto.CollectionProfile, "tls", "", true},
	} {
		c := enrollmentstate.Config{Platform: tc.platform, AutomaticRenewal: tc.renewal, Binding: enrollmentstate.Binding{Profile: tc.transport, CollectionProfile: tc.profile}}
		if got := SelfRegistrationPlatform(c); got != tc.want {
			t.Fatalf("%+v: got %q", tc, got)
		}
	}
}
