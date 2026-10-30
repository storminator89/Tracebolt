// Package rustcompat defines the public, non-authorizing Rust basic compatibility contract.
package rustcompat

const Path = "/v1/windows/rust-basic-capabilities"

type Capabilities struct {
	SchemaVersion         string `json:"schemaVersion"`
	EnrollmentProtocol    string `json:"enrollmentProtocol"`
	CollectionProfile     string `json:"collectionProfile"`
	AgentProfile          string `json:"agentProfile"`
	TelemetryFrame        string `json:"telemetryFrame"`
	ReceiptSchema         string `json:"receiptSchema"`
	EnrollmentOrigin      string `json:"enrollmentOrigin"`
	AgentOrigin           string `json:"agentOrigin"`
	AutomaticRegistration bool   `json:"automaticRegistration"`
}

func Expected(enrollmentOrigin, agentOrigin string, automaticRegistration bool) Capabilities {
	return Capabilities{"tracebolt.rust-basic-manager-capabilities.v1", "tracebolt.enrollment.v2", "windows-inventory-v1", "rust-windows-basic-v1", "tracebolt.agent-telemetry.windows.v1", "tracebolt.agent-receipt.v1", enrollmentOrigin, agentOrigin, automaticRegistration}
}
