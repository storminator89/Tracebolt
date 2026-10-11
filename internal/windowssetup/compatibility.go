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
const ReadAdminCapabilitiesPathV3 = "/v1/windows/read-admin-setup-capabilities-v3"
const ReadAdminContractV3 = "fresh-fourteen-read-admin-scopes-v1"

const ReadAdminCapabilitiesPathV4 = "/v1/windows/read-admin-setup-capabilities-v4"
const ReadAdminContractV4 = "fresh-fifteen-read-admin-scopes-v1"

const ReadAdminCapabilitiesPathV5 = "/v1/windows/read-admin-setup-capabilities-v5"
const ReadAdminContractV5 = "fresh-sixteen-read-admin-scopes-v1"

const ReadAdminCapabilitiesPathV6 = "/v1/windows/read-admin-setup-capabilities-v6"
const ReadAdminContractV6 = "fresh-seventeen-read-admin-scopes-v1"

const ReadAdminCapabilitiesPathV7 = "/v1/windows/read-admin-setup-capabilities-v7"
const ReadAdminContractV7 = "fresh-eighteen-read-admin-scopes-v1"

const ReadAdminCapabilitiesPathV8 = "/v1/windows/read-admin-setup-capabilities-v8"
const ReadAdminContractV8 = "fresh-nineteen-read-admin-scopes-v1"

const ReadAdminCapabilitiesPathV9 = "/v1/windows/read-admin-setup-capabilities-v9"
const ReadAdminContractV9 = "fresh-twenty-read-admin-scopes-v1"

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
func ExpectedReadAdminV3(manager, enrollment, agent string) Capabilities {
	c := Expected(manager, enrollment, agent)
	c.SetupContract = ReadAdminContractV3
	return c
}

func ExpectedReadAdminV4(manager, enrollment, agent string) Capabilities {
	c := Expected(manager, enrollment, agent)
	c.SetupContract = ReadAdminContractV4
	return c
}

func ExpectedReadAdminV5(manager, enrollment, agent string) Capabilities {
	c := Expected(manager, enrollment, agent)
	c.SetupContract = ReadAdminContractV5
	return c
}

func ExpectedReadAdminV6(manager, enrollment, agent string) Capabilities {
	c := Expected(manager, enrollment, agent)
	c.SetupContract = ReadAdminContractV6
	return c
}

func ExpectedReadAdminV7(manager, enrollment, agent string) Capabilities {
	c := Expected(manager, enrollment, agent)
	c.SetupContract = ReadAdminContractV7
	return c
}

func ExpectedReadAdminV8(manager, enrollment, agent string) Capabilities {
	c := Expected(manager, enrollment, agent)
	c.SetupContract = ReadAdminContractV8
	return c
}

func ExpectedReadAdminV9(manager, enrollment, agent string) Capabilities {
	c := Expected(manager, enrollment, agent)
	c.SetupContract = ReadAdminContractV9
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
	case ReadAdminContractV3:
		return ReadAdminCapabilitiesPathV3, nil
	case ReadAdminContractV4:
		return ReadAdminCapabilitiesPathV4, nil
	case ReadAdminContractV9:
		return ReadAdminCapabilitiesPathV9, nil
	case ReadAdminContractV8:
		return ReadAdminCapabilitiesPathV8, nil
	case ReadAdminContractV7:
		return ReadAdminCapabilitiesPathV7, nil
	case ReadAdminContractV6:
		return ReadAdminCapabilitiesPathV6, nil
	case ReadAdminContractV5:
		return ReadAdminCapabilitiesPathV5, nil
	}
	return "", ErrCompatibility
}

// Match accepts only the exact bounded canonical finite contract. Old or newer
// incompatible support cannot be mistaken for the exact selected receiver.
func Match(raw []byte, expected Capabilities) error {
	if len(raw) == 0 || len(raw) > 2048 || expected.SchemaVersion != CapabilitiesVersion || (expected.SetupContract != FreshReadContract && expected.SetupContract != ReadAdminContract && expected.SetupContract != ReadAdminContractV2 && expected.SetupContract != ReadAdminContractV3 && expected.SetupContract != ReadAdminContractV4 && expected.SetupContract != ReadAdminContractV5 && expected.SetupContract != ReadAdminContractV6 && expected.SetupContract != ReadAdminContractV7 && expected.SetupContract != ReadAdminContractV8 && expected.SetupContract != ReadAdminContractV9) || expected.ManagerInstanceID == "" || expected.EnrollmentOrigin == "" || expected.AgentOrigin == "" || expected.CollectionProfile != "windows-inventory-v1" {
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
