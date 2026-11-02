//go:build !linux

package operatorauth

import "context"

// Persistent live authority currently supports the Linux manager filesystem
// contract only. Other platforms fail closed; no unprotected fallback is used.
type AccountJournal struct{}

func CreateAccountJournal(string, AccountSnapshot) (*AccountJournal, error) {
	return nil, ErrConfiguration
}
func OpenAccountJournal(string) (*AccountJournal, error) { return nil, ErrConfiguration }
func (*AccountJournal) Load(context.Context) (AccountSnapshot, error) {
	return AccountSnapshot{}, ErrConfiguration
}
func (*AccountJournal) Commit(context.Context, AccountTransition) error { return ErrConfiguration }
func (*AccountJournal) ReadCredentialProposal(context.Context, string, uint64) (string, error) {
	return "", ErrConfiguration
}
func (*AccountJournal) Close() error { return nil }
