package packagecontroller

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"localrmm/internal/keyvalidation"
	"localrmm/internal/lanconfig"
	"localrmm/internal/packageupdatestore"
	"time"
)

// InitializationAuthority verifies the exact protected enrollment identity
// before create-only package setup. It must use read-only enrollment inspection.
type InitializationAuthority func(context.Context, string, string, string, time.Time) error

// Initialize creates only the durable manager record beneath an existing private
// directory. Provisioning the dedicated key, grants and endpoint acceptance is a
// separate local approval. Existing, uncertain or missing used state is never reset.
func Initialize(ctx context.Context, path string, ack bool, now time.Time, authority ...InitializationAuthority) error {
	if !ack || ctx == nil || now.Location() != time.UTC || len(authority) != 1 || authority[0] == nil {
		return ErrConfiguration
	}
	raw, e := lanconfig.ReadProtected(path, true, 8192)
	if e != nil {
		return ErrConfiguration
	}
	var c Config
	if lanconfig.StrictObject(raw, &c, "version", "enabled", "managerId", "endpointId", "incarnationDigest", "rootPolicyDigest", "transportProfile", "httpTestAcknowledged", "stateFile", "privateKeyFile", "localScopeAcknowledged") != nil || !valid(c) {
		return ErrConfiguration
	}
	if e = authority[0](ctx, c.ManagerID, c.EndpointID, c.IncarnationDigest, now); e != nil {
		return e
	}
	key, e := lanconfig.ReadProtected(c.PrivateKeyFile, true, ed25519.PrivateKeySize)
	if e != nil || len(key) != ed25519.PrivateKeySize {
		return ErrConfiguration
	}
	defer clear(key)
	derived := ed25519.NewKeyFromSeed(key[:32])
	defer clear(derived)
	if !bytes.Equal(key, derived) || !keyvalidation.Ed25519(derived.Public().(ed25519.PublicKey)) {
		return ErrConfiguration
	}
	store, e := packageupdatestore.CreateNative(ctx, c.StateFile, c.Binding(), derived.Public().(ed25519.PublicKey), now.Unix())
	if e != nil {
		return e
	}
	return store.Close()
}
