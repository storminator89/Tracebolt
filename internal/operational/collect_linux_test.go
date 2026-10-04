//go:build linux

package operational

import (
	"bytes"
	"context"
	"encoding/json"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLinuxReadOnlyCollectionIsBoundedAndValid(t *testing.T) {
	now := time.Now().UTC()
	s := Collect(context.Background(), now)
	if err := Validate(s); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(s)
	if len(b) > MaxSnapshotBytes || uint64(s.DurationMS) > MaxSafeInteger {
		t.Fatal("collection budget exceeded")
	}
	if !systemdAvailable() && (s.Sections.Services.Meta.Quality == Healthy || s.Sections.Events.Meta.Quality == Healthy) {
		t.Fatal("non-systemd host manufactured service/event success")
	}
	// Do not log raw host observations, paths, labels or package versions.
	t.Logf("valid bounded Linux snapshot: %d bytes; systemd available: %t; sections: volumes=%s network=%s processes=%s software=%s", len(b), systemdAvailable(), s.Sections.Volumes.Meta.Quality, s.Sections.Network.Meta.Quality, s.Sections.Processes.Meta.Quality, s.Sections.Software.Meta.Quality)
	if s.Sections.Processes.Meta.Quality != Healthy {
		t.Fatal("procfs host smoke did not establish actual collection")
	}
}
func TestCancelledCollectionHasNoHealthyZeros(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s := Collect(ctx, testNow())
	if Validate(s) != nil {
		t.Fatal("invalid cancellation response")
	}
	if s.Sections.Software.Meta.Quality == Healthy || s.Sections.Volumes.Meta.Quality == Healthy {
		t.Fatal("cancellation looked healthy")
	}
}
func TestFixedCommandsAndMetadataOnlyJournalSelection(t *testing.T) {
	args := strings.Join(journalArgs(testNow()), " ")
	if !strings.Contains(args, "--output-fields=__REALTIME_TIMESTAMP,_SYSTEMD_UNIT,PRIORITY,MESSAGE_ID") || strings.Contains(args, "MESSAGE,") || strings.Contains(args, "--all") || strings.Contains(args, "--follow") || !strings.Contains(args, "--lines=2049") {
		t.Fatal("journal field or output budget widened")
	}
	if strings.Join(serviceArgs(), " ") != "--system --no-pager --no-ask-password --all --property=Id,LoadState,ActiveState,SubState show *.service" {
		t.Fatal("service query widened")
	}
	if trustedTool("/bin/sh") || trustedTool("systemctl") || trustedTool("/tmp/systemctl") {
		t.Fatal("unapproved executable accepted")
	}
}
func TestBoundedReaderRejectsSymlinkFIFOAndOversize(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte("12345"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(regular, 4); err != errByteLimit {
		t.Fatal("byte cap")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(regular, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(link, 64); err == nil {
		t.Fatal("symlink accepted")
	}
	fifo := filepath.Join(dir, "fifo")
	if err := unix.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(fifo, 64); err == nil {
		t.Fatal("fifo accepted")
	}
}
func TestCommandOutputBudgetAndMountAllowlist(t *testing.T) {
	b := &cappedBuffer{limit: 3}
	if _, err := b.Write([]byte("1234")); err != errByteLimit || !b.exceeded || b.Len() != 3 {
		t.Fatal("command output unbounded")
	}
	r := mountRecord{item: Volume{Kind: "remote", Filesystem: "nfs"}, path: "/must-not-open"}
	if _, _, err := measureMount(r, []mountRecord{r}); err != errSource {
		t.Fatal("remote measurement attempted")
	}
	r.item = Volume{Kind: "local", Filesystem: "fuse.sshfs"}
	if _, _, err := measureMount(r, nil); err != errSource {
		t.Fatal("FUSE measurement attempted")
	}
	out, _ := json.Marshal(Empty(testNow(), ReasonPermissionDenied))
	if bytes.Contains(out, []byte(`"quality":"healthy"`)) {
		t.Fatal("denial looked healthy")
	}
}

func TestSingleFlightQueuedCancellationIsMeasuredWithoutCollection(t *testing.T) {
	// Hold the real admission slot without reading host sources or launching a
	// command; a queued call must not create another worker or release our slot.
	collectionSlot <- struct{}{}
	defer func() { <-collectionSlot }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	before := time.Now()
	s := Collect(ctx, testNow())
	if s.Sections.Volumes.Meta.Reason != ReasonTimeout || s.DurationMS < 10 || time.Since(before) < 10*time.Millisecond || len(collectionSlot) != 1 {
		t.Fatal("queued collection ignored deadline/admission or fabricated duration")
	}
	if Validate(s) != nil {
		t.Fatal("invalid queued timeout snapshot")
	}
}

func TestJournalCommandCannotProveCompleteCoverage(t *testing.T) {
	s := journalCoverage(parseEvents([]byte(eventFixture(testNow(), "x.service", 3, "")), testNow()))
	if s.Meta.Complete || s.Meta.CountExact || s.Meta.Reason != ReasonNotSupported || s.Meta.Quality != Healthy || len(s.Items) != 1 {
		t.Fatal("journal command manufactured full visibility")
	}
	empty := journalCoverage(parseEvents(nil, testNow()))
	if empty.Meta.Quality != Unknown || empty.Meta.Complete || empty.Meta.CountExact || empty.Meta.Reason != ReasonNotSupported {
		t.Fatal("no journal records became successful empty coverage")
	}
}
