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

// Match accepts only the exact bounded canonical finite contract. Old or newer
// incompatible support cannot be mistaken for this Setup's five-scope receiver.
func Match(raw []byte, expected Capabilities) error {
	if len(raw) == 0 || len(raw) > 2048 || expected.SchemaVersion != CapabilitiesVersion || expected.SetupContract != FreshReadContract || expected.ManagerInstanceID == "" || expected.EnrollmentOrigin == "" || expected.AgentOrigin == "" || expected.CollectionProfile != "windows-inventory-v1" {
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
