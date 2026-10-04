package lanstore

import (
	"bytes"
	"encoding/json"
	"fmt"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/linuxpackages"
	"localrmm/internal/operational"
	"strings"
	"testing"
	"time"
)

func packagesFrame(t *testing.T) (Frame, time.Time) {
	t.Helper()
	f, at := boundaryFrame(t)
	for i := range f.Observation.Observation.Evidence {
		f.Observation.Observation.Evidence[i].Detail = "fixture"
	}
	op := operational.Empty(at, operational.ReasonPermissionDenied)
	p := linuxpackages.Snapshot{SchemaVersion: linuxpackages.SchemaVersion, Scope: linuxpackages.SnapshotScope, GenerationID: op.GenerationID, CollectedAt: at, Release: linuxpackages.ReleaseObservation{Quality: linuxpackages.Unknown, Reason: linuxpackages.ReasonSourceMissing}, Inventory: linuxpackages.Inventory{Quality: linuxpackages.Denied, Reason: linuxpackages.ReasonPermissionDenied, Items: []linuxpackages.PackageRow{}}}
	f.SchemaVersion, f.Operational, f.Packages = FramePackagesVersion, &op, &p
	return f, at
}
func marshalPackageFrame(t *testing.T, f Frame) []byte {
	t.Helper()
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func packageFrameMembers(t *testing.T, f Frame) map[string]json.RawMessage {
	t.Helper()
	var members map[string]json.RawMessage
	if json.Unmarshal(marshalPackageFrame(t, f), &members) != nil {
		t.Fatal("members")
	}
	return members
}
func rawPackageMembers(t *testing.T, m map[string]json.RawMessage) []byte {
	t.Helper()
	// Marshal would compact RawMessage padding; assemble without normalization.
	var b bytes.Buffer
	b.WriteByte('{')
	for i, key := range []string{"schemaVersion", "sequence", "observation", "operational", "packages"} {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%q:", key)
		b.Write(m[key])
	}
	b.WriteByte('}')
	return b.Bytes()
}

func TestPackageFrameProfileIsolationAndUnavailableSnapshot(t *testing.T) {
	f, at := packagesFrame(t)
	decoded, err := ValidateFrame(marshalPackageFrame(t, f), at)
	if err != nil || !FrameMatchesCollectionProfile(decoded, enrollmentcrypto.CollectionProfilePackages) || decoded.Operational.CollectionProfile != operational.CollectionProfile || decoded.Packages.Inventory.Quality != linuxpackages.Denied {
		t.Fatal("new profile or explicit unavailable snapshot rejected", err)
	}
	for _, profile := range []string{enrollmentcrypto.CollectionProfile, operational.CollectionProfile, "", "managed-operations-v3"} {
		if FrameMatchesCollectionProfile(decoded, profile) {
			t.Fatal("cross-profile frame accepted", profile)
		}
	}
	for _, version := range []string{FrameVersion, FrameOperationalVersion} {
		old := f
		old.SchemaVersion = version
		if _, err := ValidateFrame(marshalPackageFrame(t, old), at); err == nil {
			t.Fatal("old schema accepted packages")
		}
		old.Packages = nil
		if version == FrameVersion {
			old.Operational = nil
		}
		if _, err := ValidateFrame(marshalPackageFrame(t, old), at); err != nil {
			t.Fatal("legacy frame rejected", err)
		}
		if FrameMatchesCollectionProfile(old, enrollmentcrypto.CollectionProfilePackages) {
			t.Fatal("new profile accepted old frame")
		}
	}
}

func TestPackageFrameStrictWireNegatives(t *testing.T) {
	for name, mutate := range map[string]func(*Frame){
		"missing-packages":   func(f *Frame) { f.Packages = nil },
		"missing-operations": func(f *Frame) { f.Operational = nil },
		"generation":         func(f *Frame) { f.Packages.GenerationID = "sample_" + strings.Repeat("0", 32) },
		"time":               func(f *Frame) { f.Packages.CollectedAt = f.Packages.CollectedAt.Add(-time.Nanosecond) },
		"operations-relabel": func(f *Frame) { f.Operational.CollectionProfile = enrollmentcrypto.CollectionProfilePackages },
		"platform":           func(f *Frame) { f.Observation.Platform = "windows" },
		"sequence":           func(f *Frame) { f.Sequence = operational.MaxSafeInteger + 1 },
		"future-basic":       func(f *Frame) { f.Observation.GeneratedAt = f.Operational.CollectedAt.Add(-time.Nanosecond) },
	} {
		t.Run(name, func(t *testing.T) {
			f, at := packagesFrame(t)
			mutate(&f)
			if _, err := ValidateFrame(marshalPackageFrame(t, f), at); err == nil {
				t.Fatal("invalid package frame accepted")
			}
		})
	}
	for name, mutate := range map[string]func([]byte) []byte{
		"duplicate": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"scope":"agent-visible-dpkg"`), []byte(`"scope":"agent-visible-dpkg","scope":"agent-visible-dpkg"`), 1)
		},
		"unknown": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"scope":"agent-visible-dpkg"`), []byte(`"scope":"agent-visible-dpkg","trusted":true`), 1)
		},
		"missing": func(b []byte) []byte { return bytes.Replace(b, []byte(`"scope":"agent-visible-dpkg",`), nil, 1) },
		"null-required": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"scope":"agent-visible-dpkg"`), []byte(`"scope":null`), 1)
		},
		"wrong-count": func(b []byte) []byte {
			return bytes.Replace(b, []byte(`"installedCount":null`), []byte(`"installedCount":"0"`), 1)
		},
		"non-z-time": func(b []byte) []byte {
			n := bytes.LastIndex(b, []byte(`123456789Z`))
			return append(append(bytes.Clone(b[:n]), []byte(`123456789+00:00`)...), b[n+10:]...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, at := packagesFrame(t)
			if _, err := ValidateFrame(mutate(marshalPackageFrame(t, f)), at); err == nil {
				t.Fatal("ambiguous JSON accepted")
			}
		})
	}
}

func TestPackageFrameRawReservationsAndWholeFrame(t *testing.T) {
	for member, cap := range map[string]int{"observation": MaxPackageObservationBytes, "operational": MaxPackageOperationalBytes, "packages": linuxpackages.MaxSnapshotBytes} {
		t.Run(member, func(t *testing.T) {
			f, at := packagesFrame(t)
			members := packageFrameMembers(t, f)
			b := members[member]
			members[member] = append(append(bytes.Clone(b[:1]), bytes.Repeat([]byte(" "), cap-len(b))...), b[1:]...)
			if _, err := ValidateFrame(rawPackageMembers(t, members), at); err != nil {
				t.Fatal("exact raw reservation rejected", err)
			}
			members[member] = append(append(bytes.Clone(members[member][:1]), ' '), members[member][1:]...)
			if _, err := ValidateFrame(rawPackageMembers(t, members), at); err == nil {
				t.Fatal("raw reservation overflow accepted")
			}
		})
	}
	f, at := packagesFrame(t)
	b := marshalPackageFrame(t, f)
	b = append(b, bytes.Repeat([]byte(" "), MaxFrameBytes-len(b))...)
	if _, err := ValidateFrame(b, at); err != nil {
		t.Fatal("exact whole-frame cap", err)
	}
	if _, err := ValidateFrame(append(b, ' '), at); err == nil {
		t.Fatal("whole-frame overflow accepted")
	}
}

func TestPackageFrameCanonicalReservationsAndAge(t *testing.T) {
	f, at := packagesFrame(t)
	// JSON may encode these without escapes, but canonical encoding must fit too.
	f.Observation.Privacy = []string{strings.Repeat("<", 3000)}
	b := bytes.ReplaceAll(marshalPackageFrame(t, f), []byte(`\u003c`), []byte("<"))
	if len(packageFrameMembers(t, f)["observation"]) <= MaxPackageObservationBytes {
		t.Fatal("canonical fixture too small")
	}
	if _, err := ValidateFrame(b, at); err == nil {
		t.Fatal("canonical observation overflow accepted")
	}
	f, at = packagesFrame(t)
	for _, now := range []time.Time{at.Add(SampleMaxAge + time.Nanosecond), at.Add(-AllowedClockSkew - time.Nanosecond)} {
		if _, err := ValidateFrame(marshalPackageFrame(t, f), now); err != ErrStale {
			t.Fatal("age/skew not enforced", err)
		}
	}
}

func TestPackageFrameCanonicalOperationsReservationAndOlderLimit(t *testing.T) {
	f, at := packagesFrame(t)
	v := &f.Operational.Sections.Volumes
	v.Meta.Quality, v.Meta.Reason, v.Meta.Complete, v.Meta.CountExact, v.Meta.ObservedCount = operational.Healthy, operational.ReasonReadFailed, false, true, 32
	for i := range 32 {
		v.Items = append(v.Items, operational.Volume{ID: fmt.Sprintf("mount_%d", i+1), MountPoint: "/" + strings.Repeat("<", 150), Filesystem: "ext4", Kind: "local", MeasurementQuality: operational.Unknown, MeasurementReason: operational.ReasonReadFailed})
	}
	if err := operational.Validate(*f.Operational); err != nil {
		t.Fatal("invalid dense operations fixture", err)
	}
	members := packageFrameMembers(t, f)
	if len(members["operational"]) <= MaxPackageOperationalBytes {
		t.Fatal("canonical fixture too small")
	}
	members["operational"] = bytes.ReplaceAll(members["operational"], []byte(`\u003c`), []byte("<"))
	if len(members["operational"]) > MaxPackageOperationalBytes {
		t.Fatal("raw fixture not below cap")
	}
	if _, err := ValidateFrame(rawPackageMembers(t, members), at); err == nil {
		t.Fatal("canonical operational reservation overflow accepted")
	}
	f.SchemaVersion = FrameOperationalVersion
	f.Packages = nil
	if _, err := ValidateFrame(marshalPackageFrame(t, f), at); err != nil {
		t.Fatal("legacy 48 KiB cap changed", err)
	}
}

func TestPackageFrameExactCanonicalReservations(t *testing.T) {
	f, at := packagesFrame(t)
	// Fill the basic reservation with otherwise-valid bounded evidence text.
	basic, _ := json.Marshal(f.Observation)
	remaining := MaxPackageObservationBytes - len(basic)
	for i := range f.Observation.Observation.Evidence {
		room := 4096 - len(f.Observation.Observation.Evidence[i].Detail)
		if room > remaining {
			room = remaining
		}
		f.Observation.Observation.Evidence[i].Detail += strings.Repeat("x", room)
		remaining -= room
	}
	if remaining != 0 {
		t.Fatal("could not fill basic reservation")
	}

	op := f.Operational
	v := &op.Sections.Software
	v.Meta.Quality, v.Meta.Reason, v.Meta.Complete, v.Meta.CountExact, v.Meta.ObservedCount = operational.Healthy, operational.ReasonNone, true, true, 160
	for i := range 160 {
		v.Items = append(v.Items, operational.Software{Name: fmt.Sprintf("package-%03d", i), Version: "1." + strings.Repeat("1", 170), Architecture: "amd64", Manager: "dpkg"})
	}
	bounded, err := operational.TrimForPackageFrame(*op)
	if err != nil {
		t.Fatal(err)
	}
	f.Operational = &bounded
	encoded, _ := json.Marshal(bounded)
	remaining = MaxPackageOperationalBytes - len(encoded)
	for i := range bounded.Sections.Software.Items {
		room := 192 - len(bounded.Sections.Software.Items[i].Version)
		if room > remaining {
			room = remaining
		}
		bounded.Sections.Software.Items[i].Version += strings.Repeat("1", room)
		remaining -= room
	}
	if remaining != 0 {
		t.Fatal("could not fill operations reservation")
	}

	count := uint64(64)
	f.Packages.Inventory = linuxpackages.Inventory{Quality: linuxpackages.Healthy, Reason: linuxpackages.ReasonNone, Complete: true, CountExact: true, ObservedCount: &count, InstalledCount: &count, Items: []linuxpackages.PackageRow{}}
	for i := range 64 {
		f.Packages.Inventory.Items = append(f.Packages.Inventory.Items, linuxpackages.PackageRow{Name: fmt.Sprintf("package-%03d", i), Version: "1", Architecture: "amd64", SourcePackage: fmt.Sprintf("source-%03d", i), SourceVersion: "1", SourceMapping: "source-field", InstallState: "installed"})
	}
	encoded, _ = json.Marshal(f.Packages)
	remaining = linuxpackages.MaxSnapshotBytes - len(encoded)
	if remaining < 0 {
		t.Fatal("package fixture initially too large")
	}
	for i := range f.Packages.Inventory.Items {
		room := 192 - len(f.Packages.Inventory.Items[i].Version)
		if room > remaining {
			room = remaining
		}
		f.Packages.Inventory.Items[i].Version += strings.Repeat("1", room)
		remaining -= room
	}
	if remaining != 0 {
		t.Fatal("could not fill package reservation")
	}
	members := packageFrameMembers(t, f)
	if len(members["observation"]) != MaxPackageObservationBytes || len(members["operational"]) != MaxPackageOperationalBytes || len(members["packages"]) != linuxpackages.MaxSnapshotBytes {
		t.Fatal("canonical reservations not exact")
	}
	if _, err := ValidateFrame(marshalPackageFrame(t, f), at); err != nil {
		t.Fatal("exact canonical reservations rejected", err)
	}

	for _, member := range []string{"observation", "operational", "packages"} {
		var larger Frame
		json.Unmarshal(marshalPackageFrame(t, f), &larger)
		switch member {
		case "observation":
			larger.Observation.Observation.Evidence[len(larger.Observation.Observation.Evidence)-1].Detail += "x"
		case "operational":
			larger.Operational.Sections.Software.Items[len(larger.Operational.Sections.Software.Items)-1].Version += "1"
		case "packages":
			larger.Packages.Inventory.Items[len(larger.Packages.Inventory.Items)-1].Version += "1"
		}
		if _, err := ValidateFrame(marshalPackageFrame(t, larger), at); err == nil {
			t.Fatal("one-byte reservation overflow accepted", member)
		}
	}
}
