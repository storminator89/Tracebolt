package native

import (
	"context"
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowseventhealth"
	"localrmm/internal/windowsnetwork"
	"localrmm/internal/windowsprocessmetrics"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsvolumes"
)

const StageCapabilities Stage = "capabilities"

type capabilityStore struct{ scope, suffix, lock, temp string }

func capabilityStores() []capabilityStore {
	return []capabilityStore{
		{windowseventhealth.Scope, "-event-metadata", "event-metadata.lock", "event-metadata.tmp"},
		{windowsvolumes.Scope, "-visible-volumes", "visible-volumes.lock", "visible-volumes.tmp"},
		{windowsprocessmetrics.Scope, "-process-metrics", "process-metrics.lock", "process-metrics.tmp"},
		{windowsnetwork.Scope, "-network", "network.lock", "network.tmp"},
	}
}
func (c capabilityStore) options(sid string) windowsstate.Options {
	return windowsstate.Options{RuntimeSID: sid, Names: []string{"consent.json"}, LockName: c.lock, TempName: c.temp, MaxBytes: 1024}
}
func (c capabilityStore) consent(insecure bool) lanclient.WindowsCapabilityConsent {
	return lanclient.WindowsCapabilityConsent{SchemaVersion: lanclient.WindowsCapabilityConsentVersionV3, CollectionProfile: enrollmentcrypto.CollectionProfileWindowsInventory, Scopes: []string{enrollmentcrypto.CollectionProfileWindowsInventory, c.scope}, Acknowledged: true, InsecureHTTPAcknowledged: insecure}
}

// ConfigureCapabilities consumes only the exact expanded, all-four-scope grant.
// Each selected write remains separate and create-only. Partial/indeterminate
// writes are retained, never rolled back or adopted by a later attempt.
func (d *Driver) ConfigureCapabilities(ctx context.Context, g Guard) error {
	if d == nil {
		return ErrAcceptance
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.enter(ctx, g, StageCapabilities) {
		return ErrAcceptance
	}
	approval, ok := g.(interface{ ExtensionsApproved() bool })
	if !ok || !d.options.Expanded || !approval.ExtensionsApproved() || !d.options.Selection.Inventory() {
		return d.fail(ReasonGuard)
	}
	return d.configureCapabilities(ctx, g)
}
