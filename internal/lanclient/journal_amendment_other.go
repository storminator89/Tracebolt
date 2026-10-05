//go:build !linux

package lanclient

func ConfigureJournalAmendment(string, string, bool, bool) (JournalAmendmentResult, error) {
	return JournalAmendmentResult{}, ErrConfiguration
}
