package alarmdelivery

import (
	"encoding/hex"
	"time"
)

func NewTestPayload(id string, now time.Time) Payload {
	return Payload{SchemaVersion: TestSchemaVersion, EventID: id, DeviceID: "synthetic", IncidentID: "synthetic", Rule: TestRule, Target: "configured-webhook", Severity: "info", Transition: "test", State: "test", Reason: "operator_requested_test", ObservedAt: now, TransitionAt: now}
}
func IsTestPayload(p Payload) bool {
	id, e := hex.DecodeString(p.EventID)
	if e != nil || len(id) != 32 || hex.EncodeToString(id) != p.EventID || p.ObservedAt.IsZero() {
		return false
	}
	return p == NewTestPayload(p.EventID, p.ObservedAt)
}
