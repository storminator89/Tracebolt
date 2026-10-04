//go:build !linux

package lanclient

func journalAgentIdentity() (uint32, uint32, bool)    { return 0, 0, false }
func loadJournalLocal(Material) (journalLocal, error) { return journalLocal{}, errJournalDisabled }
