package systeminventory

import (
	"bytes"
	"encoding/json"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SocketOwnerSourceVersion      = "tracebolt.socket-owner-source.v1"
	SocketOwnerSourceScope        = "systemd-pid1-local-tcp-udp-socket-owners"
	MaxSocketOwnerProvenanceBytes = 1024
	MaxSocketOwnerSourceDuration  = 5 * time.Second
)

// SocketOwnerProvenance records the client's authenticated helper source and
// original observation interval. Public authority/context hashes are correlation
// metadata, not bearer authority or a manager attestation of host privileges,
// complete host ownership coverage, current consent, or current helper state.
// It stays outside Snapshot so ordinary v1-v3 bytes and source scope are intact.
type SocketOwnerProvenance struct {
	SchemaVersion     string    `json:"schemaVersion"`
	Scope             string    `json:"scope"`
	GrantEpoch        string    `json:"grantEpoch"`
	PolicyDigest      string    `json:"policyDigest"`
	AuthorityRevision string    `json:"authorityRevision"`
	ContextID         string    `json:"contextId"`
	StartedAt         time.Time `json:"startedAt"`
	FinishedAt        time.Time `json:"finishedAt"`
}

// ValidateSocketOwnerProvenance binds the unmodified helper interval to the
// original full collection batch. DurationMS is truncated to whole milliseconds:
// only the upper endpoint gets a strictly sub-millisecond rounding allowance.
// Unix arithmetic avoids time.Duration overflow for otherwise valid long batches.
func ValidateSocketOwnerProvenance(p SocketOwnerProvenance, collectedAt time.Time, durationMS int64) error {
	if p.SchemaVersion != SocketOwnerSourceVersion || p.Scope != SocketOwnerSourceScope || !validTime(collectedAt) || durationMS < 0 || durationMS > MaxSafeInteger || !validTime(p.StartedAt) || !validTime(p.FinishedAt) || p.StartedAt.Before(collectedAt) || p.FinishedAt.Before(p.StartedAt) || p.FinishedAt.Sub(p.StartedAt) > MaxSocketOwnerSourceDuration {
		return ErrInvalidSnapshot
	}
	for _, value := range []string{p.GrantEpoch, p.PolicyDigest, p.AuthorityRevision, p.ContextID} {
		if len(value) != 64 || value == strings.Repeat("0", 64) {
			return ErrInvalidSnapshot
		}
		for i := range value {
			if !lowerHex(value[i]) {
				return ErrInvalidSnapshot
			}
		}
	}
	seconds := p.FinishedAt.Unix() - collectedAt.Unix()
	nanos := int64(p.FinishedAt.Nanosecond()) - int64(collectedAt.Nanosecond())
	if nanos < 0 {
		seconds--
		nanos += int64(time.Second)
	}
	if seconds*1000+nanos/int64(time.Millisecond) > durationMS {
		return ErrInvalidSnapshot
	}
	return nil
}

// DecodeSocketOwnerProvenance is an exact eight-member contract: no nulls,
// duplicate/unknown members, noncanonical identifiers or UTC time strings.
func DecodeSocketOwnerProvenance(raw []byte, collectedAt time.Time, durationMS int64) (SocketOwnerProvenance, error) {
	bad := func() (SocketOwnerProvenance, error) { return SocketOwnerProvenance{}, ErrInvalidSnapshot }
	if len(raw) == 0 || len(raw) > MaxSocketOwnerProvenanceBytes || !utf8.Valid(raw) || bytes.ContainsRune(raw, '\ufffd') {
		return bad()
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	v, err := readJSON(d, 0)
	if err != nil {
		return bad()
	}
	if _, err = d.Token(); err != io.EOF || !exactJSONType(v, reflect.TypeOf(SocketOwnerProvenance{})) {
		return bad()
	}
	var out SocketOwnerProvenance
	if json.Unmarshal(raw, &out) != nil || ValidateSocketOwnerProvenance(out, collectedAt, durationMS) != nil {
		return bad()
	}
	fields := v.(map[string]any)
	if fields["startedAt"] != out.StartedAt.Format(time.RFC3339Nano) || fields["finishedAt"] != out.FinishedAt.Format(time.RFC3339Nano) {
		return bad()
	}
	return out, nil
}
