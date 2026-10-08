package freshgate

// OutputRejection is the first guard rejection category. It contains no bytes,
// parameters, lengths, positions, titles, public trust values or error text.
type OutputRejection string

const (
	OutputNotRejected       OutputRejection = "none"
	OutputTotalLimit        OutputRejection = "output_limit"
	OutputEcho              OutputRejection = "echo"
	OutputEscapeUnsupported OutputRejection = "escape_unsupported"
	OutputCSILimit          OutputRejection = "csi_limit"
	OutputCSIUnsupported    OutputRejection = "csi_unsupported"
	OutputCSIMalformed      OutputRejection = "csi_malformed"
	OutputOSCLimit          OutputRejection = "osc_limit"
	OutputOSCMalformed      OutputRejection = "osc_malformed"
	OutputOSCUnsupported    OutputRejection = "osc_unsupported"
	OutputPostInputTitle    OutputRejection = "post_input_title"
	OutputCarriageReturn    OutputRejection = "carriage_return"
	OutputTextUnsupported   OutputRejection = "text_unsupported"
	OutputLineLimit         OutputRejection = "line_limit"
	OutputProtocol          OutputRejection = "protocol"
	OutputIncomplete        OutputRejection = "incomplete"
	OutputStateInvalid      OutputRejection = "state"
)

func (r OutputRejection) valid() bool {
	switch r {
	case OutputNotRejected, OutputTotalLimit, OutputEcho, OutputEscapeUnsupported,
		OutputCSILimit, OutputCSIUnsupported, OutputCSIMalformed, OutputOSCLimit,
		OutputOSCMalformed, OutputOSCUnsupported, OutputPostInputTitle,
		OutputCarriageReturn, OutputTextUnsupported, OutputLineLimit,
		OutputProtocol, OutputIncomplete, OutputStateInvalid:
		return true
	}
	return false
}

// RejectionReason is observable after Feed/Finish returns and after Close. Calls
// must be serialized with the guard. "none" means no rejection was recorded,
// never that complete output, no echo, or successful execution was proved.
func (g *OutputGuard) RejectionReason() OutputRejection {
	if g == nil || g.state == nil || g.state.rejection == "" {
		return OutputNotRejected
	}
	return g.state.rejection
}

func (s *outputState) reject(reason OutputRejection, err error) error {
	if s.rejection == "" {
		s.rejection = reason
	}
	return err
}
