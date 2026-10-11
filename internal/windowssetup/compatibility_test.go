package windowssetup

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCompatibilityExactAndNoExtensions(t *testing.T) {
	want := Expected("manager_00000000000000000000000000000001", "https://manager.example:8443", "https://manager.example:8444")
	raw, _ := json.Marshal(want)
	if Match(raw, want) != nil {
		t.Fatal("exact rejected")
	}
	for _, bad := range []string{"", string(raw) + "\n", string(raw) + string(raw), strings.Replace(string(raw), "fresh-five-read-scopes-v1", "fresh-five-read-scopes-v2", 1), strings.Replace(string(raw), "8444", "8445", 1), strings.Replace(string(raw), `"schemaVersion":`, `"schemaVersion":"duplicate","schemaVersion":`, 1), strings.Replace(string(raw), `"schemaVersion"`, `"SchemaVersion"`, 1), strings.TrimSuffix(string(raw), "}") + `,"extra":true}`} {
		if Match([]byte(bad), want) == nil {
			t.Fatal("incompatible accepted")
		}
	}
}

func TestReadAdminContractCannotUseFiveScopeAdvertisement(t *testing.T) {
	old := Expected("manager", "https://enroll", "https://agent")
	newer := ExpectedReadAdmin("manager", "https://enroll", "https://agent")
	a, _ := json.Marshal(old)
	b, _ := json.Marshal(newer)
	if Match(a, newer) == nil || Match(b, old) == nil || Match(b, newer) != nil {
		t.Fatal("contracts conflated")
	}
	path, e := CapabilityPath(newer)
	if e != nil || path != ReadAdminCapabilitiesPath {
		t.Fatal("wrong read-admin route")
	}
	old.SetupContract = "future"
	if _, e := CapabilityPath(old); e == nil {
		t.Fatal("unknown contract")
	}
}

func TestReadAdminV2ContractNeverPromotesHistoricalAdvertisements(t *testing.T) {
	fresh := ExpectedReadAdminV2("manager", "https://enroll", "https://agent")
	if path, e := CapabilityPath(fresh); e != nil || path != ReadAdminCapabilitiesPathV2 {
		t.Fatal("wrong fresh path", e)
	}
	contracts := []Capabilities{Expected("manager", "https://enroll", "https://agent"), ExpectedReadAdmin("manager", "https://enroll", "https://agent"), fresh}
	for i, contract := range contracts {
		raw, _ := json.Marshal(contract)
		for j, expected := range contracts {
			if (Match(raw, expected) == nil) != (i == j) {
				t.Fatal("contracts conflated", i, j)
			}
		}
	}
	raw, _ := json.Marshal(fresh)
	for _, bad := range []string{string(raw) + "\n", strings.TrimSuffix(string(raw), "}") + `,"extra":true}`, strings.Replace(string(raw), `"setupContract":`, `"setupContract":"duplicate","setupContract":`, 1)} {
		if Match([]byte(bad), fresh) == nil {
			t.Fatal("noncanonical fresh contract admitted")
		}
	}
	const legacy = `{"schemaVersion":"tracebolt.windows-setup-capabilities.v1","managerInstanceId":"manager","enrollmentOrigin":"https://enroll","agentOrigin":"https://agent","collectionProfile":"windows-inventory-v1","setupContract":"fresh-twelve-read-admin-scopes-v1"}`
	old, _ := json.Marshal(contracts[1])
	if string(old) != legacy {
		t.Fatal("historical capabilities bytes changed")
	}
}

func TestReadAdminV3StorageCannotPromoteEarlierCapabilities(t *testing.T) {
	fresh := ExpectedReadAdminV3("manager", "https://enroll", "https://agent")
	path, e := CapabilityPath(fresh)
	if e != nil || path != ReadAdminCapabilitiesPathV3 {
		t.Fatal(path, e)
	}
	contracts := []Capabilities{Expected("manager", "https://enroll", "https://agent"), ExpectedReadAdmin("manager", "https://enroll", "https://agent"), ExpectedReadAdminV2("manager", "https://enroll", "https://agent"), fresh}
	for i, c := range contracts {
		raw, _ := json.Marshal(c)
		for j, want := range contracts {
			if (Match(raw, want) == nil) != (i == j) {
				t.Fatal("contracts conflated", i, j)
			}
		}
	}
}

func TestReadAdminV4SecurityCoverageCannotPromoteEarlierCapabilities(t *testing.T) {
	fresh := ExpectedReadAdminV4("manager", "https://enroll", "https://agent")
	path, e := CapabilityPath(fresh)
	if e != nil || path != ReadAdminCapabilitiesPathV4 {
		t.Fatal(path, e)
	}
	contracts := []Capabilities{Expected("manager", "https://enroll", "https://agent"), ExpectedReadAdmin("manager", "https://enroll", "https://agent"), ExpectedReadAdminV2("manager", "https://enroll", "https://agent"), ExpectedReadAdminV3("manager", "https://enroll", "https://agent"), fresh}
	for i, c := range contracts {
		raw, _ := json.Marshal(c)
		for j, want := range contracts {
			if (Match(raw, want) == nil) != (i == j) {
				t.Fatal("contracts conflated", i, j)
			}
		}
	}
}

func TestReadAdminV5FullProcessesCannotPromoteEarlierCapabilities(t *testing.T) {
	fresh := ExpectedReadAdminV5("manager", "https://enroll", "https://agent")
	path, e := CapabilityPath(fresh)
	if e != nil || path != ReadAdminCapabilitiesPathV5 {
		t.Fatal(path, e)
	}
	contracts := []Capabilities{Expected("manager", "https://enroll", "https://agent"), ExpectedReadAdmin("manager", "https://enroll", "https://agent"), ExpectedReadAdminV2("manager", "https://enroll", "https://agent"), ExpectedReadAdminV3("manager", "https://enroll", "https://agent"), ExpectedReadAdminV4("manager", "https://enroll", "https://agent"), fresh}
	for i, c := range contracts {
		raw, _ := json.Marshal(c)
		for j, want := range contracts {
			if (Match(raw, want) == nil) != (i == j) {
				t.Fatal("contracts conflated", i, j)
			}
		}
	}
}

func TestReadAdminV6NetworkContextCannotPromoteEarlierCapabilities(t *testing.T) {
	fresh := ExpectedReadAdminV6("manager", "https://enroll", "https://agent")
	path, e := CapabilityPath(fresh)
	if e != nil || path != ReadAdminCapabilitiesPathV6 {
		t.Fatal(path, e)
	}
	contracts := []Capabilities{Expected("manager", "https://enroll", "https://agent"), ExpectedReadAdmin("manager", "https://enroll", "https://agent"), ExpectedReadAdminV2("manager", "https://enroll", "https://agent"), ExpectedReadAdminV3("manager", "https://enroll", "https://agent"), ExpectedReadAdminV4("manager", "https://enroll", "https://agent"), ExpectedReadAdminV5("manager", "https://enroll", "https://agent"), fresh}
	for i, c := range contracts {
		raw, _ := json.Marshal(c)
		for j, want := range contracts {
			if (Match(raw, want) == nil) != (i == j) {
				t.Fatal("contracts conflated", i, j)
			}
		}
	}
}

func TestReadAdminV7ResourceContextCannotPromoteEarlierCapabilities(t *testing.T) {
	fresh := ExpectedReadAdminV7("manager", "https://enroll", "https://agent")
	path, e := CapabilityPath(fresh)
	if e != nil || path != ReadAdminCapabilitiesPathV7 {
		t.Fatal(path, e)
	}
	contracts := []Capabilities{Expected("manager", "https://enroll", "https://agent"), ExpectedReadAdmin("manager", "https://enroll", "https://agent"), ExpectedReadAdminV2("manager", "https://enroll", "https://agent"), ExpectedReadAdminV3("manager", "https://enroll", "https://agent"), ExpectedReadAdminV4("manager", "https://enroll", "https://agent"), ExpectedReadAdminV5("manager", "https://enroll", "https://agent"), ExpectedReadAdminV6("manager", "https://enroll", "https://agent"), fresh}
	for i, c := range contracts {
		raw, _ := json.Marshal(c)
		for j, want := range contracts {
			if (Match(raw, want) == nil) != (i == j) {
				t.Fatal("contracts conflated", i, j)
			}
		}
	}
}

func TestReadAdminV8StorageIOCannotPromoteEarlierCapabilities(t *testing.T) {
	fresh := ExpectedReadAdminV8("manager", "https://enroll", "https://agent")
	path, e := CapabilityPath(fresh)
	if e != nil || path != ReadAdminCapabilitiesPathV8 {
		t.Fatal(path, e)
	}
	contracts := []Capabilities{Expected("manager", "https://enroll", "https://agent"), ExpectedReadAdmin("manager", "https://enroll", "https://agent"), ExpectedReadAdminV2("manager", "https://enroll", "https://agent"), ExpectedReadAdminV3("manager", "https://enroll", "https://agent"), ExpectedReadAdminV4("manager", "https://enroll", "https://agent"), ExpectedReadAdminV5("manager", "https://enroll", "https://agent"), ExpectedReadAdminV6("manager", "https://enroll", "https://agent"), ExpectedReadAdminV7("manager", "https://enroll", "https://agent"), fresh}
	for i, c := range contracts {
		raw, _ := json.Marshal(c)
		for j, want := range contracts {
			if (Match(raw, want) == nil) != (i == j) {
				t.Fatal("contracts conflated", i, j)
			}
		}
	}
}

func TestReadAdminV9SoftwareHistoryCannotPromoteEarlierCapabilities(t *testing.T) {
	fresh := ExpectedReadAdminV9("manager", "https://enroll", "https://agent")
	path, e := CapabilityPath(fresh)
	if e != nil || path != ReadAdminCapabilitiesPathV9 {
		t.Fatal(path, e)
	}
	contracts := []Capabilities{Expected("manager", "https://enroll", "https://agent"), ExpectedReadAdmin("manager", "https://enroll", "https://agent"), ExpectedReadAdminV2("manager", "https://enroll", "https://agent"), ExpectedReadAdminV3("manager", "https://enroll", "https://agent"), ExpectedReadAdminV4("manager", "https://enroll", "https://agent"), ExpectedReadAdminV5("manager", "https://enroll", "https://agent"), ExpectedReadAdminV6("manager", "https://enroll", "https://agent"), ExpectedReadAdminV7("manager", "https://enroll", "https://agent"), ExpectedReadAdminV8("manager", "https://enroll", "https://agent"), fresh}
	for i, c := range contracts {
		raw, _ := json.Marshal(c)
		for j, want := range contracts {
			if (Match(raw, want) == nil) != (i == j) {
				t.Fatal("contracts conflated", i, j)
			}
		}
	}
}

func TestReadAdminV10HistoryRequiresDistinctAdvertisement(t *testing.T) {
	fresh := ExpectedReadAdminV10("manager", "https://enroll", "https://agent")
	old := ExpectedReadAdminV9("manager", "https://enroll", "https://agent")
	raw, _ := json.Marshal(fresh)
	legacy, _ := json.Marshal(old)
	if Match(raw, fresh) != nil || Match(legacy, fresh) == nil || Match(raw, old) == nil {
		t.Fatal("history contract promoted legacy capabilities")
	}
	path, e := CapabilityPath(fresh)
	if e != nil || path != ReadAdminCapabilitiesPathV10 || path == ReadAdminCapabilitiesPathV9 {
		t.Fatal("history route not separated")
	}
}
