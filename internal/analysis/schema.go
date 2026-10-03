package analysis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// OutputSchema returns a fresh schema using the common strict-structured-output
// subset. Byte, count and reference limits are additionally enforced locally.
func OutputSchema() json.RawMessage {
	return json.RawMessage(`{"type":"object","additionalProperties":false,"required":["observedEvidenceIDs","hypotheses","counterevidence","missingData","nextCheck"],"properties":{"observedEvidenceIDs":{"type":"array","items":{"type":"string"}},"hypotheses":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["statement","evidenceIDs"],"properties":{"statement":{"type":"string"},"evidenceIDs":{"type":"array","items":{"type":"string"}}}}},"counterevidence":{"type":"array","items":{"type":"object","additionalProperties":false,"required":["statement","evidenceIDs"],"properties":{"statement":{"type":"string"},"evidenceIDs":{"type":"array","items":{"type":"string"}}}}},"missingData":{"type":"array","items":{"type":"string"}},"nextCheck":{"type":"string","enum":["none","service","storage","network"]}}}`)
}

// ValidateFindings rejects unknown fields, duplicate keys, null/missing arrays,
// unknown citations, tool-like extra fields and unbounded text. Valid citations
// establish identity only. No semantic entailment or root-cause proof is made.
func ValidateFindings(raw []byte, p Packet) (Findings, error) {
	bad := func(reason string) (Findings, error) {
		return Findings{}, fmt.Errorf("%w: %s", ErrInvalidResponse, reason)
	}
	if len(raw) > MaxResponseBytes || !utf8.Valid(raw) {
		return bad("output exceeds byte bounds or is not UTF-8")
	}
	if err := checkJSON(raw); err != nil {
		return bad("output is not one unambiguous JSON value")
	}
	obj, err := exactObject(raw, "observedEvidenceIDs", "hypotheses", "counterevidence", "missingData", "nextCheck")
	if err != nil {
		return bad("unexpected, null or missing fields")
	}
	var f Findings
	if json.Unmarshal(obj["observedEvidenceIDs"], &f.ObservedEvidenceIDs) != nil || json.Unmarshal(obj["missingData"], &f.MissingData) != nil || json.Unmarshal(obj["nextCheck"], &f.NextCheck) != nil {
		return bad("invalid field type")
	}
	if f.ObservedEvidenceIDs == nil || len(f.ObservedEvidenceIDs) > MaxEvidence || f.MissingData == nil || len(f.MissingData) > MaxMissingData || !knownRunbook(f.NextCheck) {
		return bad("field exceeds bounds")
	}
	known := map[string]bool{}
	for _, e := range p.Evidence {
		known[e.ID] = true
	}
	observed := map[string]bool{}
	for _, id := range f.ObservedEvidenceIDs {
		if !known[id] || observed[id] {
			return bad("unknown or duplicate observed evidence ID")
		}
		observed[id] = true
	}
	for _, text := range f.MissingData {
		if !outputText(text) {
			return bad("invalid missing-data text")
		}
	}
	if f.Hypotheses, err = parseClaims(obj["hypotheses"], observed); err != nil {
		return bad("invalid hypothesis or citation")
	}
	if f.Counterevidence, err = parseClaims(obj["counterevidence"], observed); err != nil {
		return bad("invalid counterevidence or citation")
	}
	return f, nil
}

func outputText(s string) bool { return strings.TrimSpace(s) != "" && bounded(s, MaxOutputTextBytes) }

func parseClaims(raw []byte, observed map[string]bool) ([]Claim, error) {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil || items == nil || len(items) > MaxClaims {
		return nil, ErrInvalidResponse
	}
	claims := make([]Claim, 0, len(items))
	for _, item := range items {
		obj, err := exactObject(item, "statement", "evidenceIDs")
		if err != nil {
			return nil, err
		}
		var c Claim
		if json.Unmarshal(obj["statement"], &c.Statement) != nil || json.Unmarshal(obj["evidenceIDs"], &c.EvidenceIDs) != nil || !outputText(c.Statement) || len(c.EvidenceIDs) == 0 || len(c.EvidenceIDs) > MaxEvidence {
			return nil, ErrInvalidResponse
		}
		seen := map[string]bool{}
		for _, id := range c.EvidenceIDs {
			if !observed[id] || seen[id] {
				return nil, ErrInvalidResponse
			}
			seen[id] = true
		}
		claims = append(claims, c)
	}
	return claims, nil
}

func exactObject(raw []byte, keys ...string) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || len(obj) != len(keys) {
		return nil, ErrInvalidResponse
	}
	for _, key := range keys {
		v, ok := obj[key]
		if !ok || bytes.Equal(bytes.TrimSpace(v), []byte("null")) {
			return nil, ErrInvalidResponse
		}
	}
	return obj, nil
}

// checkJSON rejects duplicate object members even when their spellings use JSON
// escapes, multiple top-level values and pathological nesting before decoding.
func checkJSON(raw []byte) error {
	if !utf8.Valid(raw) {
		return ErrInvalidResponse
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var walk func(int) error
	walk = func(depth int) error {
		if depth > 12 {
			return ErrInvalidResponse
		}
		tok, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := tok.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			keys := map[string]bool{}
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				s, ok := key.(string)
				if !ok || keys[s] {
					return ErrInvalidResponse
				}
				keys[s] = true
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return ErrInvalidResponse
			}
		case '[':
			for d.More() {
				if err := walk(depth + 1); err != nil {
					return err
				}
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return ErrInvalidResponse
			}
		default:
			return ErrInvalidResponse
		}
		return nil
	}
	if err := walk(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalidResponse
	}
	return nil
}
