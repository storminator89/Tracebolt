package conptyrendering

import "bytes"

// Every character is a fixed public test fixture. No identity or invitation is
// generated. The prompt is deliberately duplicated, with a source-contract test.
const publicFingerprint = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
const publicComparison = "fedcba9876543210fedcba9876543210"
const publicTrustLines = "Device SPKI SHA-256: " + publicFingerprint + "\r\nComparison: " + publicComparison + "\r\n"
const publicPrompt = "Verify public trust and enter the invitation in this console (hidden): "

// This only compares fixed public visible text. It does not interpret cursor
// editing, authorize input, or duplicate the security guard. Sequence-family
// observations remain necessary when interpreting these text predicates.
type publicTextObservation struct {
	line                                         [4096]byte
	n                                            int
	overflow, fingerprint, comparison, pendingCR bool
}

func (p *publicTextObservation) consume(c byte) {
	if c == '\r' {
		p.pendingCR = true
		return
	}
	if c == '\n' {
		p.pendingCR = false
		line := p.line[:p.n]
		if !p.overflow {
			if bytes.Equal(line, []byte("Device SPKI SHA-256: "+publicFingerprint)) {
				p.fingerprint = true
			}
			if bytes.Equal(line, []byte("Comparison: "+publicComparison)) && p.fingerprint {
				p.comparison = true
			}
		}
		clear(p.line[:])
		p.n = 0
		p.overflow = false
		return
	}
	if c < 32 || c > 126 {
		return
	}
	if p.n == len(p.line) {
		p.overflow = true
		return
	}
	p.line[p.n] = c
	p.n++
}
func (o *Observer) liveTextSummary() (trust, exact, omitted bool) {
	p := &o.public
	complete := o.state == 0 && !p.pendingCR
	return p.fingerprint && p.comparison, complete && !p.overflow && bytes.Equal(p.line[:p.n], []byte(publicPrompt)), complete && !p.overflow && bytes.Equal(p.line[:p.n], []byte(publicPrompt[:len(publicPrompt)-1]))
}
