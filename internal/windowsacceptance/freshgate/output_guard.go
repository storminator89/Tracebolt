// Package freshgate contains opt-in acceptance-test support. Its output guard
// does not open a console, start a child, perform enrollment, or grant consent.
package freshgate

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

const (
	// PublicPrompt is the exact, non-newline-terminated production prompt in
	// cmd/windows-service/operation_windows.go. It is not an invitation carrier.
	PublicPrompt = "Verify public trust and enter the invitation in this console (hidden): "
	// SuccessMarker is deliberately finite and independent of private state.
	SuccessMarker = "TRACEBOLT_FRESH_COORDINATOR_VERIFIED_V1"

	secretLength = 43
	maxOutput    = 64 << 10
	maxLine      = 4096
	maxCSI       = 64
	maxOSC       = 256

	fingerprintLabel = "Device SPKI SHA-256: "
	comparisonLabel  = "Comparison: "
)

var (
	ErrOutputGuard = errors.New("fresh console output rejected")
	ErrOutputEcho  = errors.New("synthetic console input was echoed")
	ErrOutputState = errors.New("fresh console output state invalid")
)

type vtState uint8

const (
	vtText vtState = iota
	vtEscape
	vtCSI
	vtOSC
	vtOSCEscape
)

// OutputGuard is a bounded streaming parser, not a terminal emulator. Only
// public trust values, a prompt-ready boolean and fixed errors are observable.
// Unsupported cursor editing, controls, non-ASCII output and overflows fail
// closed. In particular, do not fall back to an unguarded transcript if a real
// ConPTY produces an unsupported rendering sequence.
//
// Calls must be serialized by the owner, including Feed, PublicTrust and
// MarkInputSent. Feed borrows its argument only for the duration of the call;
// the owner must clear its own pipe-read and input-write buffers. Always defer
// Close immediately after construction. There is no transcript accessor.
type OutputGuard struct{ state *outputState }

type outputState struct {
	secret        [secretLength]byte
	prefix        [secretLength]int
	rawMatch      int
	textMatch     int
	line          [maxLine]byte
	lineLen       int
	sequence      [maxOSC]byte
	sequenceLen   int
	vt            vtState
	pendingCR     bool
	hadText       bool
	total         int
	fingerprint   [64]byte
	comparison    [32]byte
	sawFP         bool
	sawComparison bool
	promptSeen    bool
	inputSent     bool
	promptEnded   bool
	success       bool
	finished      bool
	closed        bool
	err           error
	rejection     OutputRejection
}

// Format prevents accidental fmt logging (including %#v and numeric verbs)
// from disclosing the internal mutable buffers. The value receiver contains
// only a pointer, so formatting makes no copy of those buffers.
func (OutputGuard) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "freshgate.OutputGuard{redacted}")
}
func (OutputGuard) String() string   { return "freshgate.OutputGuard{redacted}" }
func (OutputGuard) GoString() string { return "freshgate.OutputGuard{redacted}" }

// NewOutputGuard copies a locally generated canonical 43-byte base64url
// invitation into mutable memory. It neither converts that secret to a string
// nor retains the caller's slice. This is for synthetic disposable fixtures
// only; it does not authorize transmitting a real invitation.
func NewOutputGuard(secret []byte) (*OutputGuard, error) {
	if len(secret) != secretLength {
		return nil, ErrOutputState
	}
	var decoded [32]byte
	defer clear(decoded[:])
	n, err := base64.RawURLEncoding.Strict().Decode(decoded[:], secret)
	if err != nil || n != len(decoded) {
		return nil, ErrOutputState
	}
	s := &outputState{}
	copy(s.secret[:], secret)
	for i, j := 1, 0; i < len(s.secret); i++ {
		for j > 0 && s.secret[i] != s.secret[j] {
			j = s.prefix[j-1]
		}
		if s.secret[i] == s.secret[j] {
			j++
		}
		s.prefix[i] = j
	}
	return &OutputGuard{state: s}, nil
}

// Feed consumes all bytes without retaining a transcript. It scans both raw
// bytes (including title OSC payloads) and visible text with harmless VT
// sequences removed, so chunking and SGR/OSC insertion cannot hide an echo.
// CR and LF also do not reset the visible echo matcher.
func (g *OutputGuard) Feed(chunk []byte) error {
	s, err := g.active()
	if err != nil {
		return err
	}
	if len(chunk) > maxOutput-s.total {
		return s.fail(s.reject(OutputTotalLimit, ErrOutputGuard))
	}
	s.total += len(chunk)
	for _, c := range chunk {
		if s.matches(&s.rawMatch, c) {
			return s.fail(s.reject(OutputEcho, ErrOutputEcho))
		}
		if err := s.consume(c); err != nil {
			return s.fail(err)
		}
	}
	return nil
}

// PublicTrust returns only exact, newline-terminated public values, in the
// production order: one lowercase 64-hex fingerprint and one lowercase 32-hex
// comparison value. The fixture must independently validate them against its
// own pending claim before approval. Syntactic recognition is not approval.
func (g *OutputGuard) PublicTrust() (string, string, bool) {
	if g == nil || g.state == nil {
		return "", "", false
	}
	s := g.state
	if s.closed || s.err != nil || !s.sawFP || !s.sawComparison {
		return "", "", false
	}
	return string(s.fingerprint[:]), string(s.comparison[:]), true
}

// PromptReady is true only for an exact current whole line, with no partial VT
// sequence or CR pending, after the complete public values and before input.
// The prompt is intentionally not newline-terminated; the owner must call
// this only after Feed has consumed the complete available pipe-read chunk.
// An extension received in a later chunk invalidates readiness and ultimately
// fails closed; no streaming parser can predict future bytes.
func (g *OutputGuard) PromptReady() bool {
	if g == nil || g.state == nil {
		return false
	}
	s := g.state
	return !s.closed && !s.finished && s.err == nil && !s.inputSent &&
		s.sawFP && s.sawComparison && s.promptSeen && s.vt == vtText &&
		!s.pendingCR && bytes.Equal(s.line[:s.lineLen], []byte(PublicPrompt))
}

// MarkInputSent transitions exactly once at the prompt barrier. The owner
// must serialize this immediately before its one bounded synthetic input
// write, and fail the entire test if that write is incomplete or fails. A
// success marker received before this transition is never accepted.
func (g *OutputGuard) MarkInputSent() error {
	s, err := g.active()
	if err != nil {
		return err
	}
	if !g.PromptReady() {
		return s.fail(s.reject(OutputStateInvalid, ErrOutputState))
	}
	s.inputSent = true
	return nil
}

// Finish must be called only after confirmed child exit and drained pipe EOF.
// It requires the exact newline-terminated marker, complete parser state and
// no trailing text. A marker does not itself establish child exit, activation,
// grants, cleanup, or native acceptance; those are separate owner checks.
func (g *OutputGuard) Finish() error {
	s, err := g.active()
	if err != nil {
		return err
	}
	if s.vt != vtText || s.pendingCR || s.lineLen != 0 || !s.sawFP ||
		!s.sawComparison || !s.promptEnded || !s.inputSent || !s.success {
		return s.fail(s.reject(OutputIncomplete, ErrOutputGuard))
	}
	s.finished = true
	s.clearSensitive()
	return nil
}

// Close clears all owned mutable buffers. It is idempotent. Go does not
// guarantee erasure of compiler/runtime copies; no stronger claim is made.
func (g *OutputGuard) Close() {
	if g == nil || g.state == nil {
		return
	}
	s := g.state
	s.clearSensitive()
	clear(s.fingerprint[:])
	clear(s.comparison[:])
	s.closed = true
}

func (g *OutputGuard) active() (*outputState, error) {
	if g == nil || g.state == nil {
		return nil, ErrOutputState
	}
	s := g.state
	if s.err != nil {
		return nil, s.err
	}
	if s.closed || s.finished {
		return nil, ErrOutputState
	}
	return s, nil
}

func (s *outputState) fail(err error) error {
	if s.err == nil {
		s.err = err
	}
	s.clearSensitive()
	clear(s.fingerprint[:])
	clear(s.comparison[:])
	return s.err
}

func (s *outputState) clearSensitive() {
	clear(s.secret[:])
	clear(s.prefix[:])
	clear(s.line[:])
	clear(s.sequence[:])
	s.rawMatch, s.textMatch, s.lineLen, s.sequenceLen = 0, 0, 0, 0
}

func (s *outputState) matches(matched *int, c byte) bool {
	for *matched > 0 && c != s.secret[*matched] {
		*matched = s.prefix[*matched-1]
	}
	if c == s.secret[*matched] {
		*matched = *matched + 1
	}
	return *matched == len(s.secret)
}

func (s *outputState) consume(c byte) error {
	switch s.vt {
	case vtEscape:
		switch c {
		case '[':
			s.vt = vtCSI
		case ']':
			s.vt = vtOSC
		default:
			return s.reject(OutputEscapeUnsupported, ErrOutputGuard)
		}
		return nil
	case vtCSI:
		if s.sequenceLen == maxCSI {
			return s.reject(OutputCSILimit, ErrOutputGuard)
		}
		if c >= 0x40 && c <= 0x7e {
			if !s.validCSI(c) {
				return s.reject(OutputCSIUnsupported, ErrOutputGuard)
			}
			s.endSequence()
			return nil
		}
		if c < 0x20 || c > 0x3f {
			return s.reject(OutputCSIMalformed, ErrOutputGuard)
		}
		s.sequence[s.sequenceLen] = c
		s.sequenceLen++
		return nil
	case vtOSC:
		if c == '\a' {
			return s.endOSC()
		}
		if c == 0x1b {
			s.vt = vtOSCEscape
			return nil
		}
		if c < 0x20 || c > 0x7e {
			return s.reject(OutputOSCMalformed, ErrOutputGuard)
		}
		if s.sequenceLen == maxOSC {
			return s.reject(OutputOSCLimit, ErrOutputGuard)
		}
		s.sequence[s.sequenceLen] = c
		s.sequenceLen++
		return nil
	case vtOSCEscape:
		if c != '\\' {
			return s.reject(OutputOSCMalformed, ErrOutputGuard)
		}
		return s.endOSC()
	}
	if c == 0x1b {
		s.vt = vtEscape
		return nil
	}
	if s.pendingCR {
		if c != '\n' {
			return s.reject(OutputCarriageReturn, ErrOutputGuard)
		}
		s.pendingCR = false
	}
	switch c {
	case '\r':
		s.pendingCR = true
		return nil
	case '\n':
		return s.endLine()
	}
	if c < 0x20 || c > 0x7e {
		return s.reject(OutputTextUnsupported, ErrOutputGuard)
	}
	if s.lineLen == maxLine {
		return s.reject(OutputLineLimit, ErrOutputGuard)
	}
	if s.success {
		return s.reject(OutputProtocol, ErrOutputGuard)
	}
	if s.matches(&s.textMatch, c) {
		return s.reject(OutputEcho, ErrOutputEcho)
	}
	s.hadText = true
	s.line[s.lineLen] = c
	s.lineLen++
	if bytes.Equal(s.line[:s.lineLen], []byte(PublicPrompt)) {
		if s.promptSeen || !s.sawFP || !s.sawComparison || s.inputSent {
			return s.reject(OutputProtocol, ErrOutputGuard)
		}
		s.promptSeen = true
	}
	return nil
}

func (s *outputState) endSequence() {
	clear(s.sequence[:])
	s.sequenceLen = 0
	s.vt = vtText
}

func (s *outputState) endOSC() error {
	// Only ordinary window/icon titles are admitted. OSC 8 hyperlinks, OSC 52
	// clipboard access, shell integration and all other commands are rejected.
	p := s.sequence[:s.sequenceLen]
	if s.inputSent && len(p) > 2 {
		return s.reject(OutputPostInputTitle, ErrOutputGuard)
	}
	if len(p) < 2 || (p[0] != '0' && p[0] != '2') || p[1] != ';' {
		return s.reject(OutputOSCUnsupported, ErrOutputGuard)
	}
	s.endSequence()
	return nil
}

func (s *outputState) validCSI(final byte) bool {
	p := s.sequence[:s.sequenceLen]
	if (final == 'h' || final == 'l') && bytes.Equal(p, []byte("?25")) {
		return true // Cursor visibility does not change the text model.
	}
	if (final == 'h' || final == 'l') &&
		(bytes.Equal(p, []byte("?9001")) || bytes.Equal(p, []byte("?1004"))) {
		// Exact ConPTY Win32-input/focus-reporting requests do not render text.
		// This pipe client retains plain-text input compatibility and has no
		// focus events to report. See the documented compatibility rationale;
		// do not generalize this to other private modes or parameter lists.
		return true
	}
	if (final == 'h' || final == 'l') && bytes.Equal(p, []byte("?1003;1006")) {
		// Exact ConPTY any-event mouse reporting + SGR mouse encoding pair.
		// These requests do not render text; this headless pipe client has no
		// mouse event source and sends no mouse reports or acknowledgement.
		// Admit only this observed ordering and its documented reset partner,
		// never arbitrary private-mode lists. See the compatibility rationale.
		return true
	}
	if !s.hadText && !s.pendingCR && s.lineLen == 0 {
		if final == 'J' && bytes.Equal(p, []byte("2")) {
			return true // Clear the initial, known-empty screen only.
		}
		if final == 'H' && (len(p) == 0 || bytes.Equal(p, []byte("1;1"))) {
			return true // Home before the first visible text only.
		}
	}
	if final != 'm' {
		return false
	}
	// Admit only common, non-concealing presentation attributes. Unknown SGR,
	// extended colors and conceal are deliberately unsupported, not guessed.
	value, digits := 0, 0
	for i := 0; i <= len(p); i++ {
		if i == len(p) || p[i] == ';' {
			if !allowedSGR(value) {
				return false
			}
			value, digits = 0, 0
			continue
		}
		if p[i] < '0' || p[i] > '9' || digits == 3 {
			return false
		}
		value = value*10 + int(p[i]-'0')
		digits++
	}
	return true
}

func allowedSGR(n int) bool {
	switch n {
	case 0, 1, 2, 3, 4, 5, 7, 9, 21, 22, 23, 24, 25, 27, 29, 39, 49:
		return true
	}
	return n >= 30 && n <= 37 || n >= 40 && n <= 47 ||
		n >= 90 && n <= 97 || n >= 100 && n <= 107
}

func (s *outputState) endLine() error {
	line := s.line[:s.lineLen]
	defer func() {
		clear(s.line[:])
		s.lineLen = 0
	}()
	if bytes.Equal(line, []byte(PublicPrompt)) {
		if !s.promptSeen || !s.inputSent || s.promptEnded {
			return s.reject(OutputProtocol, ErrOutputGuard)
		}
		s.promptEnded = true
		return nil
	}
	if bytes.Equal(line, []byte(SuccessMarker)) {
		if !s.sawFP || !s.sawComparison || !s.promptEnded || !s.inputSent || s.success {
			return s.reject(OutputProtocol, ErrOutputGuard)
		}
		s.success = true
		return nil
	}
	if s.promptSeen || s.inputSent || s.success {
		if len(line) == 0 && s.promptEnded {
			return nil
		}
		return s.reject(OutputProtocol, ErrOutputGuard)
	}
	if bytes.HasPrefix(line, []byte("Device SPKI SHA-256:")) {
		if s.sawFP || s.sawComparison || !publicHexLine(line, fingerprintLabel, 64) {
			return s.reject(OutputProtocol, ErrOutputGuard)
		}
		copy(s.fingerprint[:], line[len(fingerprintLabel):])
		s.sawFP = true
		return nil
	}
	if bytes.HasPrefix(line, []byte("Comparison:")) {
		if !s.sawFP || s.sawComparison || !publicHexLine(line, comparisonLabel, 32) {
			return s.reject(OutputProtocol, ErrOutputGuard)
		}
		copy(s.comparison[:], line[len(comparisonLabel):])
		s.sawComparison = true
		return nil
	}
	// Unrelated public production disclosures are discarded, never returned.
	return nil
}

func publicHexLine(line []byte, label string, n int) bool {
	if len(line) != len(label)+n || !bytes.HasPrefix(line, []byte(label)) {
		return false
	}
	for _, c := range line[len(label):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
