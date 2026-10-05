package lanclient

import "localrmm/internal/journalgeneration"

// JournalAmendmentResult contains public policy/identity metadata only. It is a
// local setup result, never collection authorization or a log-content response.
type JournalAmendmentResult struct {
	SchemaVersion          string                  `json:"schemaVersion"`
	Mode                   string                  `json:"mode"`
	Scope                  string                  `json:"scope"`
	SenderBinding          string                  `json:"senderBinding"`
	ManagerOrigin          string                  `json:"managerOrigin"`
	TransportProfile       string                  `json:"transportProfile"`
	CollectionProfile      string                  `json:"collectionProfile"`
	DeviceID               string                  `json:"deviceId"`
	CertificateHash        string                  `json:"certificateHash"`
	AgentUID               uint32                  `json:"agentUid"`
	AgentGID               uint32                  `json:"agentGid"`
	PolicyDigest           string                  `json:"policyDigest"`
	PolicyGeneration       journalgeneration.Tuple `json:"policyGeneration,omitzero"`
	Accepted               bool                    `json:"accepted"`
	ExistingStatePreserved bool                    `json:"existingStatePreserved"`
}
