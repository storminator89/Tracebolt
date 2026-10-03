package enrollmenttransport

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"time"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
	"localrmm/internal/enrollmentstore"
	"localrmm/internal/lantrust"
)

// publicAuthorizer is request-scoped. Its snapshot only carries the final
// lookup's invitation to SaveObservation; it is never reusable authorization.
type publicAuthorizer struct {
	store    *enrollmentstore.Store
	ctx      context.Context
	now      func() time.Time
	snapshot enrollmentstate.Snapshot
}

func (a *publicAuthorizer) AuthorizePublicCertificate(publicPEM []byte) (lantrust.Agent, error) {
	if a == nil || a.store == nil || a.ctx == nil || a.now == nil {
		return lantrust.Agent{}, lantrust.ErrRegistryUnavailable
	}
	a.snapshot = enrollmentstate.Snapshot{}
	if len(publicPEM) == 0 || len(publicPEM) > 2*enrollmentcrypto.MaxCertificateBytes || !bytes.HasPrefix(publicPEM, []byte("-----BEGIN CERTIFICATE-----\n")) {
		return lantrust.Agent{}, lantrust.ErrUnauthorized
	}
	block, rest := pem.Decode(publicPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) != 0 || !bytes.Equal(publicPEM, pem.EncodeToMemory(block)) {
		return lantrust.Agent{}, lantrust.ErrUnauthorized
	}
	snapshot, err := a.store.AuthorizeCertificate(a.ctx, block.Bytes, a.now())
	if err != nil {
		if errors.Is(err, enrollmentstore.ErrStorage) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return lantrust.Agent{}, lantrust.ErrRegistryUnavailable
		}
		return lantrust.Agent{}, lantrust.ErrUnauthorized
	}
	a.snapshot = snapshot
	return lantrust.Agent{ID: snapshot.Approval.DeviceID, Label: snapshot.Approval.DeviceID, FingerprintSHA256: snapshot.Issuance.CertificateHash, ApprovedAt: time.Unix(snapshot.Approval.At, 0).UTC(), NotBefore: time.Unix(snapshot.Intent.NotBefore, 0).UTC(), ExpiresAt: time.Unix(snapshot.Intent.NotAfter, 0).UTC()}, nil
}
