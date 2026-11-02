package windowsmanagedmsi

// AccountEpochs are manager-only approval receipts. They are not included in
// signed endpoint permits or scope grants. Missing means historical/unbound;
// a live account manager must deny it rather than adopting current authority.
func (r Record) AccountEpochKeys() map[string]bool {
	keys := map[string]bool{}
	for _, raw := range [][]byte{r.DeliveryPermit, r.ReadinessPermit, r.InstallPermit, r.RetirePermit} {
		if len(raw) > 0 {
			keys[Digest(raw)] = true
		}
	}
	if r.Schedule != nil {
		keys[r.Schedule.Approval.Digest] = true
	}
	return keys
}
func (r Record) validateAccountEpochs() error {
	if len(r.AccountEpochs) > 5 {
		return ErrIntegrity
	}
	keys := r.AccountEpochKeys()
	for key, epoch := range r.AccountEpochs {
		if !keys[key] || !ValidDigest(key) || epoch == 0 {
			return ErrIntegrity
		}
	}
	return nil
}
func accountEpochTransition(before, after Record) error {
	oldKeys, newKeys := before.AccountEpochKeys(), after.AccountEpochKeys()
	for key, epoch := range before.AccountEpochs {
		if newKeys[key] && after.AccountEpochs[key] != epoch {
			return ErrConsumed
		}
	}
	for key, epoch := range after.AccountEpochs {
		if oldKeys[key] && before.AccountEpochs[key] != epoch {
			return ErrConsumed
		}
	}
	return nil
}
