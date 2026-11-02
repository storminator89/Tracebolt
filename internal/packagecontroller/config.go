package packagecontroller

import "localrmm/internal/lanconfig"

const MaxConfigBytes = 8192

// ParseConfig is the shared, bounded configuration-only validation boundary.
// It performs no filesystem access, credential read, authority check or store
// opening. An offline inventory planner may inspect the external StateFile and
// PrivateKeyFile dependencies without invoking Load and starting a state session.
//
// Success is not operational admission: callers must still perform the existing
// exact identity, current-grant, signing-key and durable-state checks. This one
// domain does not provide a complete manager inventory or a stopped-writer fence.
func ParseConfig(raw []byte) (Config, error) {
	var c Config
	if len(raw) == 0 || len(raw) > MaxConfigBytes ||
		lanconfig.StrictObject(raw, &c, "version", "enabled", "managerId", "endpointId", "incarnationDigest", "rootPolicyDigest", "transportProfile", "httpTestAcknowledged", "stateFile", "privateKeyFile", "localScopeAcknowledged") != nil || !valid(c) {
		return Config{}, ErrConfiguration
	}
	return c, nil
}
