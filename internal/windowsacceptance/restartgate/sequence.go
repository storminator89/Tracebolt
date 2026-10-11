package restartgate

// Sequence is single-owner admission bookkeeping, not host authority. Every
// failed transition is irreversible. There is no retry, reset or compensation.
type Sequence struct {
	phase   uint8
	unknown bool
}

func NewSequence() *Sequence { return &Sequence{} }
func (s *Sequence) transition(from, to uint8, valid bool) error {
	if s == nil {
		return ErrRejected
	}
	if s.unknown || s.phase != from || !valid {
		s.unknown = true
		return ErrUnknown
	}
	s.phase = to
	return nil
}
func (s *Sequence) BeginRejection() error { return s.transition(0, 1, true) }
func (s *Sequence) ConfirmRejection(c CommandResult, sameProcess, leaseVerified bool) error {
	return s.transition(1, 2, c.Exited && !c.Uncertain && sameProcess && leaseVerified && ValidateCLI(c.Stdout, c.ExitCode, true) == nil)
}
func (s *Sequence) ReleaseLease(clean bool) error { return s.transition(2, 3, clean) }
func (s *Sequence) BeginRestart() error           { return s.transition(3, 4, true) }
func (s *Sequence) ConfirmRestart(c CommandResult) error {
	return s.transition(4, 5, c.Exited && !c.Uncertain && !c.StderrSeen && ValidateCLI(c.Stdout, c.ExitCode, false) == nil)
}
func (s *Sequence) MarkUnknown() {
	if s != nil {
		s.unknown = true
	}
}
func (s *Sequence) Ready() bool { return s != nil && !s.unknown && s.phase == 5 }
