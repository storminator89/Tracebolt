package enrollmentservice

import (
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/model"
	"reflect"
	"strings"
	"testing"
)

func TestProfileCapabilitiesPreserveBasicAndUnknownScope(t *testing.T) {
	in := []model.Capability{{ID: "systemd", Status: "unsupported", Detail: "systemd is not queried"}, {ID: "remote_actions", Status: "unsupported"}}
	for _, profile := range []string{"", enrollmentcrypto.CollectionProfile, "managed-operations-v99"} {
		if got := profileCapabilities(in, profile); !reflect.DeepEqual(got, in) {
			t.Fatalf("profile %q widened basic capabilities", profile)
		}
	}
}

func TestProfileCapabilitiesCompleteScopeIsNotObservedSuccess(t *testing.T) {
	in := []model.Capability{
		{ID: "cpu", Name: "CPU", Status: "limited", Detail: "Stale or unknown metric"},
		{ID: "systemd", Name: "Service inventory", Status: "unsupported", Detail: "systemd and other service managers are not queried."},
		{ID: "journal", Name: "System logs", Status: "denied", Detail: "Source permission denied"},
		{ID: "remote_actions", Name: "Remote actions", Status: "unsupported", Detail: "No process inventory"},
	}
	before := append([]model.Capability(nil), in...)
	got := profileCapabilities(in, enrollmentcrypto.CollectionProfileComplete)
	if !reflect.DeepEqual(in, before) || !reflect.DeepEqual(got[0], in[0]) {
		t.Fatal("projection mutated stored capabilities or metric quality")
	}
	seen := map[string]model.Capability{}
	for _, c := range got {
		if _, duplicate := seen[c.ID]; duplicate {
			t.Fatal("duplicate capability")
		}
		seen[c.ID] = c
		if c.Status == "supported" || strings.Contains(c.Detail, "not queried") || strings.Contains(c.Detail, "No process inventory") {
			t.Fatal("invented success or retained contradictory basic-only detail")
		}
	}
	if seen["journal"].Status != "denied" || seen["remote_actions"].Status != "unsupported" || seen["systemd"].Status != "scope" || seen["package_inventory"].Status != "scope" || seen["socket_inventory"].Status != "scope" {
		t.Fatal("scope projection promoted denied/unknown observations or remote control")
	}
	if !strings.Contains(seen["journal"].Detail, "excludes message bodies") || !strings.Contains(seen["socket_inventory"].Detail, "does not establish external reachability") {
		t.Fatal("source/privacy limits missing")
	}
	got[0].Detail = "changed output"
	if !reflect.DeepEqual(in, before) {
		t.Fatal("projection aliases stored capability slice")
	}
}

func TestProfileCapabilitiesOlderManagedScopeDoesNotClaimCompleteInventory(t *testing.T) {
	for _, profile := range []string{enrollmentcrypto.CollectionProfileOperational, enrollmentcrypto.CollectionProfilePackages} {
		got := profileCapabilities(nil, profile)
		if len(got) != 3 {
			t.Fatal("older managed profile acquired complete package/socket capability")
		}
		for _, c := range got {
			if c.ID == "package_inventory" || c.ID == "socket_inventory" || c.Status == "supported" || strings.Contains(c.Detail, "paged systemd") {
				t.Fatal("older managed profile silently widened")
			}
		}
	}
}

func TestProfileCapabilitiesOptionalIdentityDoesNotChangeOSQuality(t *testing.T) {
	for _, status := range []string{"supported", "limited", "denied", "unsupported"} {
		in := []model.Capability{{ID: "os", Name: "Operating system", Status: status, Detail: "No hostname is collected."}}
		out := profileCapabilities(in, enrollmentcrypto.CollectionProfileComplete)
		if out[0].Status != status || out[0].Name != in[0].Name || !strings.Contains(out[0].Detail, "after local opt-in") || !strings.Contains(out[0].Detail, "original age") || in[0].Detail != "No hostname is collected." {
			t.Fatal("optional identity description changed source quality or retained obsolete scope")
		}
		for _, profile := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational, enrollmentcrypto.CollectionProfilePackages} {
			if profileCapabilities(in, profile)[0] != in[0] {
				t.Fatal("older profile acquired optional identity scope")
			}
		}
	}
}

func TestOptionalJournalContentNeedsSeparatePermissionAndDoesNotPromoteDeniedMetadata(t *testing.T) {
	in := []model.Capability{{ID: "journal", Name: "System logs", Status: "denied", Detail: "Metadata read denied"}}
	got := profileCapabilities(in, enrollmentcrypto.CollectionProfileComplete)
	found := false
	for _, c := range got {
		if c.ID == "journal" && c.Status != "denied" {
			t.Fatal("optional helper promoted denied metadata")
		}
		if c.ID == "journal_content" {
			found = true
			if c.Status != "scope" || !strings.Contains(c.Detail, "separate local helper/content permission") || !strings.Contains(c.Detail, "may contain secrets") || !strings.Contains(c.Detail, "does not establish") {
				t.Fatal("optional access advertised as established")
			}
		}
	}
	if !found {
		t.Fatal("missing optional journal scope")
	}
	for _, p := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational, enrollmentcrypto.CollectionProfilePackages, "unknown"} {
		for _, c := range profileCapabilities(in, p) {
			if c.ID == "journal_content" {
				t.Fatal("older profile widened")
			}
		}
	}
	if in[0].Detail != "Metadata read denied" {
		t.Fatal("source slice changed")
	}
}

func TestCompleteOverviewCapabilitiesRequireOptInWithoutInventedSuccess(t *testing.T) {
	in := []model.Capability{{ID: "complete_process_inventory", Status: "denied", Detail: "inert fixture denial"}}
	for _, profile := range []string{enrollmentcrypto.CollectionProfile, enrollmentcrypto.CollectionProfileOperational, enrollmentcrypto.CollectionProfilePackages, "unknown"} {
		for _, row := range profileCapabilities(nil, profile) {
			if row.ID == "complete_process_inventory" || row.ID == "complete_mount_inventory" {
				t.Fatal("older profile widened")
			}
		}
	}
	found := 0
	for _, row := range profileCapabilities(in, enrollmentcrypto.CollectionProfileComplete) {
		if row.ID != "complete_process_inventory" && row.ID != "complete_mount_inventory" {
			continue
		}
		found++
		if !strings.Contains(row.Detail, "explicit local complete-overview consent") || !strings.Contains(row.Detail, "namespace") || row.Status == "supported" {
			t.Fatal("optional overview promoted to source success")
		}
		if row.ID == "complete_process_inventory" && row.Status != "denied" {
			t.Fatal("denied source promoted")
		}
	}
	if found != 2 || in[0].Detail != "inert fixture denial" {
		t.Fatal("missing optional scope or source mutation")
	}
}

func TestCompleteCapabilitiesSeparateScopeFromObservedFailure(t *testing.T) {
	for _, in := range [][]model.Capability{nil, {{ID: "socket_owner_metadata", Status: "denied", Detail: "fixed denial"}}} {
		out := profileCapabilities(in, enrollmentcrypto.CollectionProfileComplete)
		seen := false
		for _, row := range out {
			if row.ID != "socket_owner_metadata" {
				continue
			}
			seen = true
			want := "scope"
			if len(in) != 0 {
				want = "denied"
			}
			if row.Status != want || !strings.Contains(row.Detail, "not complete attribution") {
				t.Fatal("helper scope was confused with observed success or denied access")
			}
		}
		if !seen {
			t.Fatal("missing independent owner coverage disclosure")
		}
	}
}
