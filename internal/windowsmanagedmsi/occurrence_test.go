package windowsmanagedmsi

import "testing"

func TestReusableOccurrenceReferencesUseFloorEvenForIdenticalCustody(t *testing.T) {
	artifact := &Artifact{NativeAcceptanceDigest: Digest([]byte("same metadata and custody"))}
	current := ArtifactRecord{Version: ReusableArtifactRecordVersion, RetiredCount: 2, Artifact: artifact}
	old := Record{Grant: Grant{Version: ReusableGrantVersion}, Artifact: artifact, ArtifactRetiredCount: 0, RetiredReport: []byte("validated by store before comparison")}
	if matches, err := ReferencesArtifactOccurrence(old, current); err != nil || matches {
		t.Fatal("retired same-content older occurrence aliased current", matches, err)
	}
	old.RetiredReport = nil
	if _, err := ReferencesArtifactOccurrence(old, current); err != ErrUncertain {
		t.Fatal("unresolved older evidence discarded", err)
	}
	old.ArtifactRetiredCount = 3
	if _, err := ReferencesArtifactOccurrence(old, current); err != ErrIntegrity {
		t.Fatal("future occurrence accepted", err)
	}
	old.ArtifactRetiredCount = 2
	if matches, err := ReferencesArtifactOccurrence(old, current); err != nil || !matches {
		t.Fatal("exact occurrence lost", err)
	}
	different := *artifact
	different.IntentAt++
	old.Artifact = &different
	if _, err := ReferencesArtifactOccurrence(old, current); err != ErrIntegrity {
		t.Fatal("same floor accepted different custody", err)
	}
}
