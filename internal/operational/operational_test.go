package operational

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

func testNow() time.Time { return time.Date(2026, 10, 3, 22, 0, 0, 0, time.UTC) }
func TestEmptyIsExplicitAndValid(t *testing.T) {
	s := Empty(testNow(), ReasonNotSupported)
	if err := Validate(s); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(s)
	if bytes.Contains(b, []byte(`"items":null`)) {
		t.Fatal("nil items")
	}
	if s.Sections.Software.Meta.Complete || s.Sections.Volumes.Meta.Quality != Unknown || s.GenerationID == Empty(testNow(), ReasonNotSupported).GenerationID {
		t.Fatal("missing evidence looked complete or observation ID reused")
	}
}
func TestValidationRejectsUnsafeOrInconsistentValues(t *testing.T) {
	cases := map[string]func(*Snapshot){
		"schema":           func(s *Snapshot) { s.SchemaVersion = "other" },
		"profile":          func(s *Snapshot) { s.CollectionProfile = "basic-readonly-v1" },
		"label":            func(s *Snapshot) { s.GenerationID = "sample_bad" },
		"duration":         func(s *Snapshot) { s.DurationMS = int64(MaxSafeInteger) + 1 },
		"null items":       func(s *Snapshot) { s.Sections.Volumes.Items = nil },
		"stale input":      func(s *Snapshot) { s.Sections.Volumes.Meta.Quality = "stale" },
		"pretend complete": func(s *Snapshot) { s.Sections.Volumes.Meta.Complete = true },
		"bad reason":       func(s *Snapshot) { s.Sections.Volumes.Meta.Reason = "raw private diagnostic" },
		"count":            func(s *Snapshot) { s.Sections.Volumes.Meta.ObservedCount = MaxSafeInteger + 1 },
		"bad time":         func(s *Snapshot) { s.CollectedAt = s.CollectedAt.In(time.FixedZone("offset", 3600)) },
		"controls": func(s *Snapshot) {
			s.Sections.Processes = available[Process](s.CollectedAt, ProcessLimit)
			s.Sections.Processes.Items = []Process{{PID: 1, Name: "x\nsecret", State: "running"}}
			s.Sections.Processes.Meta.ObservedCount = 1
		},
		"nan": func(s *Snapshot) {
			s.Sections.Processes = available[Process](s.CollectedAt, ProcessLimit)
			s.Sections.Processes.Items = []Process{{PID: 1, Name: "x", State: "running", CPUTimeSeconds: pointer(math.NaN())}}
			s.Sections.Processes.Meta.ObservedCount = 1
		},
		"path": func(s *Snapshot) {
			s.Sections.Processes = available[Process](s.CollectedAt, ProcessLimit)
			s.Sections.Processes.Items = []Process{{PID: 1, Name: "/private/bin/x", State: "running"}}
			s.Sections.Processes.Meta.ObservedCount = 1
		},
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			s := Empty(testNow(), ReasonSourceMissing)
			change(&s)
			if Validate(s) == nil {
				t.Fatal("accepted invalid snapshot")
			}
		})
	}
}
func TestMountParsingRedactsAndClassifiesWithoutSources(t *testing.T) {
	data := []byte("29 1 8:1 / /home/private-user/data rw,secret=password - ext4 /dev/disk/by-uuid/private-uuid rw\n30 1 0:4 / /remote rw - nfs4 server:/private rw\n31 1 0:5 / /run/user/1001 rw - fuse.sshfs secret@server:/ rw\n32 1 0:6 / /sys rw - sysfs sysfs rw\n")
	s, rows := parseMounts(data, testNow())
	if len(rows) != 4 || s.Meta.ObservedCount != 4 || !s.Meta.CountExact {
		t.Fatal("mount discovery")
	}
	if rows[0].item.MountPoint != "/home/[redacted]/data" || rows[2].item.MountPoint != "/run/user/[redacted]" || rows[1].item.Kind != "remote" || rows[2].item.Kind != "remote" || rows[3].item.Kind != "virtual" {
		t.Fatal("mount privacy/classification")
	}
	for _, r := range rows {
		s.Items = append(s.Items, r.item)
		partial(&s.Meta, r.item.MeasurementReason, false)
	}
	b, _ := json.Marshal(s)
	for _, secret := range []string{"private-user", "1001", "password", "private-uuid", "secret@", "server:"} {
		if bytes.Contains(b, []byte(secret)) {
			t.Fatal("mount source escaped")
		}
	}
	for _, input := range []string{`/x\040y`, `/x\134y`} {
		if _, ok := decodeMount(input); !ok {
			t.Fatal("safe mount escape rejected")
		}
	}
	for _, input := range []string{`/x\012y`, `/x\077y`, "relative"} {
		if _, ok := decodeMount(input); ok {
			t.Fatal("unsafe mount escape accepted")
		}
	}
}
func statFixture(pid int, name string, rss int) []byte {
	f := []string{"S", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "123", "77", "0", "0", "0", "0", "2", "0", "0", "0", fmt.Sprint(rss)}
	return []byte(fmt.Sprintf("%d (%s) %s\n", pid, name, strings.Join(f, " ")))
}
func TestProcessStatMetadataAndHighRSSPriority(t *testing.T) {
	p, ok := parseProcessStat(statFixture(17, "worker (io)", 20), 17, 4096)
	if !ok || p.PID != 17 || *p.RSSBytes != 81920 || *p.CPUTimeSeconds != 2 || *p.Threads != 2 || p.State != "sleeping" {
		t.Fatal("proc fields")
	}
	for _, pageBytes := range []uint64{16384, 65536} {
		p, ok := parseProcessStat(statFixture(17, "worker (io)", 20), 17, pageBytes)
		if !ok || *p.RSSBytes != 20*pageBytes || *p.CPUTimeSeconds != 2 {
			t.Fatal("ARM64 page size changed RSS or USER_HZ semantics")
		}
	}
	if _, ok = parseProcessStat(statFixture(17, "/path/private", 20), 17, 4096); ok {
		t.Fatal("path in process name")
	}
	if _, ok = parseProcessStat(statFixture(17, "worker", -1), 17, 4096); ok {
		t.Fatal("negative counter accepted")
	}
	s := available[Process](testNow(), ProcessLimit)
	for i := 1; i <= 100; i++ {
		p, ok := parseProcessStat(statFixture(i, "worker", i), uint64(i), 4096)
		if !ok {
			t.Fatal("fixture")
		}
		s.Items = append(s.Items, p)
	}
	s.Meta.ObservedCount = 100
	sortProcesses(&s)
	if len(s.Items) != 64 || s.Items[0].PID != 100 || s.Items[63].PID != 37 || !s.Meta.Truncated || s.Meta.Complete || !s.Meta.CountExact {
		t.Fatal("highest RSS or coverage lost")
	}
}
func TestNetworkOnlyCountersNoAddresses(t *testing.T) {
	data := []byte("Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\neth0: 100 1 2 0 0 0 0 0 200 1 3 0 0 0 0 0\nlo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n")
	s := parseNetwork(data, testNow())
	if len(s.Items) != 2 || s.Items[0].Name != "eth0" || *s.Items[0].RXBytes != 100 || *s.Items[0].TXErrors != 3 || s.Items[0].IPv4Count != nil || s.Items[0].IPv6Count != nil {
		t.Fatal("interface metadata")
	}
}
func TestServiceFailuresFirstAndUnknownStatesVisible(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 140; i++ {
		state, sub := "active", "running"
		if i == 139 {
			state, sub = "failed", "failed"
		}
		fmt.Fprintf(&b, "Id=unit%d.service\nLoadState=loaded\nActiveState=%s\nSubState=%s\n\n", i, state, sub)
	}
	s := parseServices([]byte(b.String()), testNow())
	if len(s.Items) != 128 || s.Items[0].Name != "unit139.service" || s.Meta.ObservedCount != 140 || !s.Meta.Truncated || s.Meta.Complete {
		t.Fatal("failed unit dropped or truncation hidden")
	}
	s = parseServices([]byte("Id=x.service\nLoadState=novel\nActiveState=novel\nSubState=novel\n"), testNow())
	if len(s.Items) != 1 || s.Items[0].LoadState != "unknown" || s.Items[0].ActiveState != "unknown" || s.Meta.Complete {
		t.Fatal("unknown state invented")
	}
}
func TestSoftwareIsInstalledDeterministicBoundedSample(t *testing.T) {
	var b strings.Builder
	for i := 300; i >= 0; i-- {
		fmt.Fprintf(&b, "Package: package-%03d\nStatus: install ok installed\nVersion: 1.0-1\nArchitecture: amd64\nDescription: private prose never exported\nMaintainer: private-contact\n\n", i)
	}
	b.WriteString("Package: absent\nStatus: deinstall ok config-files\n\n")
	s := parseSoftware(context.Background(), strings.NewReader(b.String()), testNow())
	if len(s.Items) != 256 || s.Items[0].Name != "package-000" || s.Items[255].Name != "package-255" || s.Meta.ObservedCount != 301 || s.Meta.Complete || !s.Meta.Truncated || !s.Meta.CountExact {
		t.Fatal("dpkg sample incorrect")
	}
	out, _ := json.Marshal(s)
	if bytes.Contains(out, []byte("private")) {
		t.Fatal("package extra fields escaped")
	}
	bad := parseSoftware(context.Background(), strings.NewReader("Package: partial\nStatus: bad\n"), testNow())
	if bad.Meta.Quality != Unknown || len(bad.Items) != 0 {
		t.Fatal("invalid dpkg source became success")
	}
}
func eventFixture(at time.Time, unit string, priority int, extra string) string {
	return fmt.Sprintf(`{"__REALTIME_TIMESTAMP":"%d","_SYSTEMD_UNIT":%q,"PRIORITY":"%d","MESSAGE_ID":"0123456789abcdef0123456789abcdef","_BOOT_ID":"discarded"%s}`+"\n", at.UnixMicro(), unit, priority, extra)
}
func TestEventMetadataGroupsAndNeverIncludesMessage(t *testing.T) {
	now := testNow()
	input := eventFixture(now.Add(-time.Minute), "x.service", 3, "") + eventFixture(now.Add(-2*time.Minute), "x.service", 3, "")
	s := parseEvents([]byte(input), now)
	if len(s.Items) != 1 || s.Items[0].Count != 2 || s.Meta.ObservedCount != 2 || !s.Meta.Complete || s.Items[0].FirstSeen != now.Add(-2*time.Minute) {
		t.Fatal("aggregation")
	}
	snap := Empty(now, ReasonSourceMissing)
	snap.Sections.Events = s
	stampGeneration(&snap)
	if err := Validate(snap); err != nil {
		t.Fatal("aggregate failed validation", err)
	}
	out, _ := json.Marshal(s)
	if bytes.Contains(out, []byte("_BOOT_ID")) || bytes.Contains(out, []byte("discarded")) {
		t.Fatal("journal identity escaped")
	}
	for _, bad := range []string{eventFixture(now, "x.service", 3, `,"MESSAGE":"secret text"`), eventFixture(now.Add(-16*time.Minute), "x.service", 3, ""), eventFixture(now.Add(time.Second), "x.service", 3, ""), eventFixture(now, "x.service", 8, "")} {
		v := parseEvents([]byte(bad), now)
		if len(v.Items) != 0 || v.Meta.Quality != Unknown || v.Meta.Complete {
			t.Fatal("invalid/raw/out of window journal accepted")
		}
	}
}
func TestByteLimitPreservesFailuresAndDeterministicSample(t *testing.T) {
	s := Empty(testNow(), ReasonSourceMissing)
	s.Sections.Software = available[Software](testNow(), SoftwareLimit)
	for i := 0; i < SoftwareLimit; i++ {
		s.Sections.Software.Items = append(s.Sections.Software.Items, Software{Name: fmt.Sprintf("package-%03d", i) + strings.Repeat("x", 110), Version: "1." + strings.Repeat("1", 189), Architecture: "amd64", Manager: "dpkg"})
	}
	s.Sections.Software.Meta.ObservedCount = SoftwareLimit
	s.Sections.Services = available[Service](testNow(), ServiceLimit)
	s.Sections.Services.Items = []Service{{Name: "failed.service", LoadState: "loaded", ActiveState: "failed", SubState: "failed"}}
	s.Sections.Services.Meta.ObservedCount = 1
	stampGeneration(&s)
	copy := s
	copy.Sections.Software.Items = append([]Software(nil), s.Sections.Software.Items...)
	trimSnapshot(&s)
	trimSnapshot(&copy)
	a, _ := json.Marshal(s)
	b, _ := json.Marshal(copy)
	if len(a) > MaxSnapshotBytes || !bytes.Equal(a, b) || len(s.Sections.Services.Items) != 1 || !s.Sections.Software.Meta.Truncated || s.Sections.Software.Meta.Reason != ReasonByteLimit || s.Sections.Software.Meta.ObservedCount != 256 {
		t.Fatal("budget was nondeterministic or dropped failure")
	}
	if err := Validate(s); err != nil {
		t.Fatal(err)
	}
}

func TestEmptyReasonsRemainValid(t *testing.T) {
	for _, reason := range []Reason{ReasonNone, ReasonSourceMissing, ReasonPermissionDenied, ReasonNotSupported, ReasonTimeout, ReasonInvalidSource, ReasonReadFailed, ReasonItemLimit, ReasonByteLimit, ReasonRemoteFilesystemSkipped, ReasonToolUnavailable, ReasonNotImplemented, "unexpected"} {
		if err := Validate(Empty(testNow(), reason)); err != nil {
			t.Fatalf("reason %s: %v", reason, err)
		}
	}
}
func TestMalformedAndFilteredSourcesAreNotHealthyEmpty(t *testing.T) {
	n := parseNetwork([]byte("header\nheader\ngarbage\n"), testNow())
	if n.Meta.Quality != Unknown || n.Meta.Complete || len(n.Items) != 0 {
		t.Fatal("malformed interfaces looked healthy")
	}
	s := parseServices([]byte("Description=should never be requested\n"), testNow())
	if s.Meta.Quality != Unknown || s.Meta.Complete || len(s.Items) != 0 {
		t.Fatal("unselected service property looked healthy")
	}
	input := "Package: " + strings.Repeat("a", 129) + "\nStatus: install ok installed\nVersion: 1.0\nArchitecture: amd64\n\n"
	p := parseSoftware(context.Background(), strings.NewReader(input), testNow())
	if p.Meta.Quality != Unknown || p.Meta.Complete || len(p.Items) != 0 || p.Meta.ObservedCount != 1 {
		t.Fatal("filtered package source looked healthy")
	}
}
func TestDropLastDoesNotEraseLastGoodEligibilityWithHealthyEmpty(t *testing.T) {
	s := available[Service](testNow(), ServiceLimit)
	s.Items = []Service{{Name: "x.service", LoadState: "loaded", ActiveState: "failed", SubState: "failed"}}
	s.Meta.ObservedCount = 1
	dropLast(&s)
	if s.Meta.Quality != Unknown || s.Meta.Reason != ReasonByteLimit || s.Meta.Complete || !s.Meta.Truncated || s.Meta.ObservedCount != 1 {
		t.Fatal("omitted section became empty success")
	}
}
func TestEventSourceDuplicateAndScopeMetadata(t *testing.T) {
	input := eventFixture(testNow(), "x.service", 3, `,"PRIORITY":"1"`)
	s := parseEvents([]byte(input), testNow())
	if len(s.Items) != 0 || s.Meta.Quality != Unknown {
		t.Fatal("duplicate journal fields accepted")
	}
	s = parseEvents([]byte(eventFixture(testNow(), "system.slice", 3, "")), testNow())
	if len(s.Items) != 1 || s.Items[0].Unit != "system.slice" {
		t.Fatal("typed nonservice unit rejected")
	}
}
func TestRetainedSectionValidatorsPreserveIndependentProvenance(t *testing.T) {
	old := Empty(testNow().Add(-time.Hour), ReasonSourceMissing)
	fresh := Empty(testNow(), ReasonSourceMissing)
	if ValidateVolumeSection(old.Sections.Volumes) != nil || ValidateNetworkSection(old.Sections.Network) != nil || ValidateServiceSection(old.Sections.Services) != nil || ValidateProcessSection(old.Sections.Processes) != nil || ValidateSoftwareSection(old.Sections.Software) != nil || ValidateEventSection(old.Sections.Events) != nil {
		t.Fatal("standalone unavailable section rejected")
	}
	fresh.Sections.Services = old.Sections.Services
	if Validate(fresh) == nil {
		t.Fatal("mixed raw snapshot generation accepted")
	}
	bad := old.Sections.Services
	bad.Meta.GenerationID = ""
	if ValidateServiceSection(bad) == nil {
		t.Fatal("missing retained provenance accepted")
	}
}

func TestPartialSourceCapsAlwaysMarkTruncation(t *testing.T) {
	for _, reason := range []Reason{ReasonByteLimit, ReasonItemLimit} {
		s := available[Service](testNow(), ServiceLimit)
		partial(&s.Meta, reason, false)
		if s.Meta.Complete || !s.Meta.Truncated {
			t.Fatal("provider limit omitted truncation")
		}
	}
}

func TestJournalNullOrBinaryMetadataIsNotSilentlyMissing(t *testing.T) {
	for _, value := range []string{"null", "[120]"} {
		input := fmt.Sprintf(`{"__REALTIME_TIMESTAMP":"%d","_SYSTEMD_UNIT":%s,"PRIORITY":"3"}`, testNow().UnixMicro(), value)
		s := parseEvents([]byte(input), testNow())
		if s.Meta.Quality != Unknown || len(s.Items) != 0 || s.Meta.Reason != ReasonInvalidSource {
			t.Fatal("nonstring journal field became missing success")
		}
	}
}

func TestRetainedSoftwareSectionCannotExceedSnapshotBudget(t *testing.T) {
	s := available[Software](testNow(), SoftwareLimit)
	s.Meta.GenerationID = Empty(testNow(), ReasonSourceMissing).GenerationID
	for i := 0; i < SoftwareLimit; i++ {
		s.Items = append(s.Items, Software{Name: fmt.Sprintf("package-%03d", i) + strings.Repeat("x", 110), Version: "1." + strings.Repeat("1", 189), Architecture: "amd64", Manager: "dpkg"})
	}
	s.Meta.ObservedCount = SoftwareLimit
	if ValidateSoftwareSection(s) == nil {
		t.Fatal("oversized retained section accepted")
	}
}
