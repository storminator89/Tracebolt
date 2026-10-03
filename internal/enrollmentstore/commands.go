package enrollmentstore

import (
	"context"

	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/enrollmentstate"
)

func (s *Store) command(ctx context.Context, action func(*transaction) (enrollmentstate.Snapshot, error)) (enrollmentstate.Snapshot, error) {
	var out enrollmentstate.Snapshot
	err := s.transact(ctx, func(t *transaction) error { var err error; out, err = action(t); return err })
	if err != nil {
		return enrollmentstate.Snapshot{}, err
	}
	return out, nil
}
func (s *Store) CreateInvitation(ctx context.Context, c enrollmentstate.CreateCommand) (enrollmentstate.Snapshot, error) {
	return s.command(ctx, func(t *transaction) (enrollmentstate.Snapshot, error) { return t.engine.CreateInvitation(ctx, c) })
}
func (s *Store) Claim(ctx context.Context, c enrollmentstate.ClaimCommand, proof enrollmentcrypto.VerifiedClaim) (enrollmentstate.Snapshot, error) {
	return s.command(ctx, func(t *transaction) (enrollmentstate.Snapshot, error) { return t.engine.Claim(ctx, c, proof) })
}
func (s *Store) Approve(ctx context.Context, c enrollmentstate.ApproveCommand) (enrollmentstate.Snapshot, error) {
	return s.command(ctx, func(t *transaction) (enrollmentstate.Snapshot, error) { return t.engine.Approve(ctx, c) })
}
func (s *Store) BeginIssuance(ctx context.Context, c enrollmentstate.IntentCommand) (enrollmentstate.Snapshot, error) {
	return s.command(ctx, func(t *transaction) (enrollmentstate.Snapshot, error) { return t.engine.BeginIssuance(ctx, c) })
}
func (s *Store) Terminate(ctx context.Context, c enrollmentstate.TerminalCommand) (enrollmentstate.Snapshot, error) {
	return s.command(ctx, func(t *transaction) (enrollmentstate.Snapshot, error) { return t.engine.Terminate(ctx, c) })
}
func (s *Store) Activate(ctx context.Context, c enrollmentstate.Control, proof enrollmentcrypto.VerifiedActivation) (enrollmentstate.Snapshot, error) {
	return s.command(ctx, func(t *transaction) (enrollmentstate.Snapshot, error) { return t.engine.Activate(ctx, c, proof) })
}

// CommitIssued stores the exact DER, immutable intent and empty delivery/replay
// ledger in the same commit as the issued lifecycle transition. An exact retry
// retains the first DER and all later metadata. No signing occurs here.
func (s *Store) CommitIssued(ctx context.Context, c enrollmentstate.Control, proof enrollmentcrypto.VerifiedCertificate) (enrollmentstate.Snapshot, error) {
	return s.command(ctx, func(t *transaction) (enrollmentstate.Snapshot, error) {
		out, err := t.engine.CommitIssued(ctx, c, proof)
		if err != nil {
			return enrollmentstate.Snapshot{}, err
		}
		if _, ok := t.credentials[c.InvitationID]; !ok {
			t.credentials[c.InvitationID] = credential{DER: proof.DER()}
		}
		return out, nil
	})
}
func (s *Store) Get(ctx context.Context, id string) (enrollmentstate.Snapshot, error) {
	return s.command(ctx, func(t *transaction) (enrollmentstate.Snapshot, error) { return t.engine.Get(id) })
}
func (s *Store) Snapshots(ctx context.Context) ([]enrollmentstate.Snapshot, error) {
	var out []enrollmentstate.Snapshot
	err := s.transact(ctx, func(t *transaction) error { out = t.engine.Snapshots(); return nil })
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SigningIntent returns only an already committed, still authorized intent.
// Signers must use IntentID as their idempotency key and reconcile uncertain
// results without creating another identity/serial. A later cancellation can
// still reject CommitIssued; signing is not authority to return a credential.
func (s *Store) SigningIntent(ctx context.Context, id string, now int64) (enrollmentcrypto.Intent, error) {
	var out enrollmentcrypto.Intent
	err := s.transact(ctx, func(t *transaction) error { var err error; out, err = t.engine.SigningIntent(id, now); return err })
	if err != nil {
		return enrollmentcrypto.Intent{}, err
	}
	return out, nil
}

// StatusContext is a privileged internal lookup for cryptographic verification.
// Returned public metadata does not authorize an endpoint response or delivery;
// the verified proof must be checked again in the final durable transaction.
func (s *Store) StatusContext(ctx context.Context, id string) (enrollmentstate.Snapshot, []byte, error) {
	var key []byte
	snapshot, err := s.command(ctx, func(t *transaction) (enrollmentstate.Snapshot, error) {
		snapshot, err := t.engine.Get(id)
		if err != nil {
			return enrollmentstate.Snapshot{}, err
		}
		key, err = t.engine.TrustedClaimKey(id)
		return snapshot, err
	})
	if err != nil {
		return enrollmentstate.Snapshot{}, nil, err
	}
	return snapshot, key, nil
}

// Config returns an immutable value copy of public manager/profile constraints.
// It contains neither invitation verifiers nor private signing material.
func (s *Store) Config() enrollmentstate.Config {
	if s == nil || s.storeState == nil {
		return enrollmentstate.Config{}
	}
	return s.config
}
