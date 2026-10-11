// Package windowssetup defines public Setup/manager protocol compatibility.
// It never authorizes installation, enrollment, trust or collection.
package windowssetup

import (
	"bytes"
	"encoding/json"
	"errors"
)

const CapabilitiesPath = "/v1/windows/setup-capabilities"
const CapabilitiesVersion = "tracebolt.windows-setup-capabilities.v1"
const FreshReadContract = "fresh-five-read-scopes-v1"
const ReadAdminCapabilitiesPath = "/v1/windows/read-admin-setup-capabilities"
const ReadAdminContract = "fresh-twelve-read-admin-scopes-v1"

// V2 is a distinct public route; the old advertisements retain exact bytes.
const ReadAdminCapabilitiesPathV2 = "/v1/windows/read-admin-setup-capabilities-v2"
const ReadAdminContractV2 = "fresh-thirteen-read-admin-scopes-v1"

var ErrCompatibility = errors.New("manager is unavailable or does not support this Windows Setup contract; update the manager and obtain a new Windows bootstrap export")

// Capabilities binds finite protocol support to the public bootstrap's manager.
// No invitation, identity, telemetry or secret is returned on this route.
type Capabilities struct {
	SchemaVersion     string `json:"schemaVersion"`
	ManagerInstanceID string `json:"managerInstanceId"`
	EnrollmentOrigin  string `json:"enrollmentOrigin"`
	AgentOrigin       string `json:"agentOrigin"`
	CollectionProfile string `json:"collectionProfile"`
	SetupContract     string `json:"setupContract"`
}

func Expected(manager, enrollment, agent string) Capabilities {
	return Capabilities{CapabilitiesVersion, manager, enrollment, agent, "windows-inventory-v1", FreshReadContract}
}

func ExpectedReadAdmin(manager, enrollment, agent string) Capabilities {
	c := Expected(manager, enrollment, agent)
	c.SetupContract = ReadAdminContract
	return c
}

func ExpectedReadAdminV2(manager, enrollment, agent string) Capabilities {
	c := Expected(manager, enrollment, agent)
	c.SetupContract = ReadAdminContractV2
	return c
}

func CapabilityPath(c Capabilities) (string, error) {
	switch c.SetupContract {
	case FreshReadContract:
		return CapabilitiesPath, nil
	case ReadAdminContract:
		return ReadAdminCapabilitiesPath, nil
	case ReadAdminContractV2:
		return ReadAdminCapabilitiesPathV2, nil
	}
	return "", ErrCompatibility
}

// Match accepts only the exact bounded canonical finite contract. Old or newer
// incompatible support cannot be mistaken for the exact selected receiver.
func Match(raw []byte, expected Capabilities) error {
	if len(raw) == 0 || len(raw) > 2048 || expected.SchemaVersion != CapabilitiesVersion || (expected.SetupContract != FreshReadContract && expected.SetupContract != ReadAdminContract && expected.SetupContract != ReadAdminContractV2) || expected.ManagerInstanceID == "" || expected.EnrollmentOrigin == "" || expected.AgentOrigin == "" || expected.CollectionProfile != "windows-inventory-v1" {
		return ErrCompatibility
	}
	var got Capabilities
	if json.Unmarshal(raw, &got) != nil || got != expected {
		return ErrCompatibility
	}
	canonical, err := json.Marshal(got)
	if err != nil || !bytes.Equal(raw, canonical) {
		return ErrCompatibility
	}
	return nil
}
