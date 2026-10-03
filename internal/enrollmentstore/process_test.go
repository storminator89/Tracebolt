package enrollmentstore

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"sync"
	"testing"

	"localrmm/internal/enrollmentstate"
)

func TestIndependentProcessHelper(t *testing.T) {
	if os.Getenv("TRACEBOLT_ENROLLMENT_TEST_CHILD") != "1" {
		t.Skip("subprocess fixture only")
	}
	var config enrollmentstate.Config
	raw, err := base64.RawStdEncoding.DecodeString(os.Getenv("TRACEBOLT_ENROLLMENT_TEST_CONFIG"))
	if err != nil || json.Unmarshal(raw, &config) != nil {
		t.Fatal("invalid public fixture config")
	}
	issuer, err := base64.RawStdEncoding.DecodeString(os.Getenv("TRACEBOLT_ENROLLMENT_TEST_ISSUER"))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(os.Getenv("TRACEBOLT_ENROLLMENT_TEST_PATH"), config, issuer)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	_, err = s.Terminate(context.Background(), enrollmentstate.TerminalCommand{Control: enrollmentstate.Control{InvitationID: id("invite", 1), RequestID: id("request", 9), ExpectedRevision: 1, Now: testNow + 1}, State: enrollmentstate.Canceled})
	if err != nil {
		t.Fatal(err)
	}
}
func TestIndependentProcessesSerializeTerminalRetry(t *testing.T) {
	f, s, path := fixtureStore(t)
	if _, err := s.CreateInvitation(context.Background(), f.createCommand()); err != nil {
		t.Fatal(err)
	}
	config, _ := json.Marshal(f.config)
	env := append(os.Environ(), "TRACEBOLT_ENROLLMENT_TEST_CHILD=1", "TRACEBOLT_ENROLLMENT_TEST_CONFIG="+base64.RawStdEncoding.EncodeToString(config), "TRACEBOLT_ENROLLMENT_TEST_ISSUER="+base64.RawStdEncoding.EncodeToString(f.issuerDER), "TRACEBOLT_ENROLLMENT_TEST_PATH="+path)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cmd := exec.Command(os.Args[0], "-test.run=^TestIndependentProcessHelper$")
			cmd.Env = env
			errs <- cmd.Run()
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal("independent process transaction failed:", err)
		}
	}
	snapshot, err := s.Get(context.Background(), id("invite", 1))
	if err != nil || snapshot.State != enrollmentstate.Canceled || snapshot.Revision != 2 {
		t.Fatal("processes did not converge on one retained tombstone")
	}
}
