package setupgate

import (
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func uninstallFixtureStatus(ok bool) UninstallHeldStatus {
	if ok {
		return UninstallStatusObserved
	}
	return UninstallStatusFailed
}

func TestUninstallPendingPredicateAndReadOrderUnchanged(t *testing.T) {
	for bits := 0; bits < 16; bits++ {
		pending, statusOK, stopped, closed := bits&1 != 0, bits&2 != 0, bits&4 != 0, bits&8 != 0
		var calls []string
		o := ObserveUninstallPending(pending, func() (UninstallHeldStatus, bool) {
			calls = append(calls, "held-status")
			return uninstallFixtureStatus(statusOK), stopped
		}, func() bool {
			calls = append(calls, "close")
			return closed
		})
		if o.Ready() != (pending && statusOK && stopped && !closed) {
			t.Fatalf("predicate changed for combination %d", bits)
		}
		var want []string
		if pending {
			want = append(want, "held-status")
			if statusOK && stopped {
				want = append(want, "close")
			}
		}
		if !reflect.DeepEqual(calls, want) {
			t.Fatalf("read order changed for combination %d", bits)
		}
		if !Contains(Stages, o.Stage("")) {
			t.Fatal("observation emitted an unregistered stage")
		}
	}
}

func TestUninstallPendingSequenceDoesNotLatchEarlierSuccess(t *testing.T) {
	for _, sample := range []struct {
		text                              string
		pending, statusOK, stopped, close bool
		ready                             bool
		stage                             string
	}{
		{stage: "uninstall-pending-text"},
		{text: uninstallStopping, stage: "uninstall-stopping"},
		{text: uninstallRemoving, stage: "uninstall-removing"},
		{pending: true, stage: "uninstall-held-status"},
		{pending: true, statusOK: true, stage: "uninstall-held-stopped"},
		{pending: true, statusOK: true, stopped: true, ready: true, stage: "uninstall"},
		{pending: true, statusOK: true, stopped: true, close: true, stage: "uninstall-pending-close"},
		{text: "finite diagnostic\r\n\r\n" + uninstallInterrupted, stage: "uninstall-operation-failed"},
	} {
		o := ObserveUninstallPending(sample.pending, func() (UninstallHeldStatus, bool) { return uninstallFixtureStatus(sample.statusOK), sample.stopped }, func() bool { return sample.close })
		if o.Ready() != sample.ready || o.Stage(sample.text) != sample.stage {
			t.Fatal("sequence observation or failed boundary was lost")
		}
	}
}

func TestUninstallProgressOnlyRecognizesExactBoundedParagraphs(t *testing.T) {
	o := ObserveUninstallPending(false, nil, nil)
	for _, sample := range []struct{ text, stage string }{
		{uninstallInterrupted, "uninstall-operation-failed"},
		{"public diagnostic\r\n\r\n" + uninstallInterrupted, "uninstall-operation-failed"},
		{uninstallStopping, "uninstall-stopping"},
		{uninstallRemoving, "uninstall-removing"},
		{"private text contains " + uninstallInterrupted, "uninstall-pending-text"},
		{uninstallInterrupted + " private suffix", "uninstall-pending-text"},
		{"private path and error", "uninstall-pending-text"},
		{strings.Repeat("x", 32<<10) + "\r\n\r\n" + uninstallInterrupted, "uninstall-pending-text"},
	} {
		if o.Stage(sample.text) != sample.stage || o.Ready() {
			t.Fatal("arbitrary text became diagnostic authority or acceptance")
		}
		if !Contains(Stages, sample.stage) {
			t.Fatal("progress emitted an unregistered stage")
		}
	}
}

func TestUninstallHeldCloseDistinguishesFailureFromCompletion(t *testing.T) {
	for _, sample := range []struct{ text, stage string }{
		{uninstallInterrupted, "uninstall-held-close-failed"},
		{"public diagnostic\r\n\r\n" + uninstallInterrupted, "uninstall-held-close-failed"},
		{uninstallCompleted, "uninstall-held-close-completed"},
		{"Service removal confirmed.\r\n\r\n" + uninstallCompleted, "uninstall-held-close-completed"},
		{uninstallCompleted + "\r\n\r\n" + uninstallInterrupted, "uninstall-held-close-failed"},
		{"Service removal confirmed", "uninstall-held-close"},
		{"private " + uninstallCompleted, "uninstall-held-close"},
		{"", "uninstall-held-close"},
	} {
		if UninstallHeldCloseStage(sample.text) != sample.stage || !Contains(Stages, sample.stage) {
			t.Fatal("held Close diagnostic was lost or not finite")
		}
	}
}

func TestUninstallHeldQueryFailuresAreFiniteAndCannotPass(t *testing.T) {
	for _, sample := range []struct {
		status UninstallHeldStatus
		stage  string
	}{
		{UninstallStatusFailed, "uninstall-held-status"},
		{UninstallStatusDeletePending, "uninstall-held-status-delete-pending"},
		{UninstallStatusInvalidHandle, "uninstall-held-status-invalid-handle"},
		{UninstallStatusAccessDenied, "uninstall-held-status-access-denied"},
		{UninstallHeldStatus(255), "uninstall-held-status"},
	} {
		o := ObserveUninstallPending(true, func() (UninstallHeldStatus, bool) { return sample.status, true }, func() bool {
			t.Fatal("Close queried after rejected SCM query")
			return false
		})
		if o.Ready() || o.Stage("private error") != sample.stage || !Contains(Stages, sample.stage) {
			t.Fatal("native query error accepted or leaked")
		}
	}
}

func TestUninstallPendingCloseClassifiesOutcomeWithoutAcceptingIt(t *testing.T) {
	o := ObserveUninstallPending(true, func() (UninstallHeldStatus, bool) { return UninstallStatusObserved, true }, func() bool { return true })
	for _, sample := range []struct{ text, stage string }{
		{uninstallInterrupted, "uninstall-pending-close-failed"},
		{uninstallCompleted, "uninstall-pending-close-completed"},
		{uninstallCompleted + "\r\n\r\n" + uninstallInterrupted, "uninstall-pending-close-failed"},
		{"private " + uninstallInterrupted, "uninstall-pending-close"},
	} {
		if o.Ready() || o.Stage(sample.text) != sample.stage || !Contains(Stages, sample.stage) {
			t.Fatal("pending Close was accepted or misclassified")
		}
	}
}

func TestUninstallMissingObserverDoesNotSucceed(t *testing.T) {
	if ObserveUninstallPending(true, nil, nil).Ready() || ObserveUninstallPending(true, func() (UninstallHeldStatus, bool) { return UninstallStatusObserved, true }, nil).Ready() {
		t.Fatal("missing observer accepted")
	}
}

func TestUninstallDiagnosticParagraphsMatchExistingProductionText(t *testing.T) {
	for path, paragraphs := range map[string][]string{
		"../../windowssetupui/ui.go":                   {uninstallInterrupted, uninstallCompleted},
		"../../../cmd/windows-service/setup_wizard.go": {uninstallStopping, uninstallRemoving},
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal("could not inspect production diagnostic constants")
		}
		for _, paragraph := range paragraphs {
			if !strings.Contains(string(raw), strconv.Quote(paragraph)) {
				t.Fatal("diagnostic fixture drifted from existing production text")
			}
		}
	}
}
