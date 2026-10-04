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
	if seen["journal"].Status != "denied" || seen["remote_actions"].Status != "unsupported" || seen["systemd"].Status != "limited" || seen["package_inventory"].Status != "limited" || seen["socket_inventory"].Status != "limited" {
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
			if c.Status != "limited" || !strings.Contains(c.Detail, "separate local helper/content permission") || !strings.Contains(c.Detail, "may contain secrets") || !strings.Contains(c.Detail, "does not establish") {
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
