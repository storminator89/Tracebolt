//go:build linux

package operatorauth

import (
	"bytes"
	"context"
	"encoding/base32"
	"encoding/json"
	"io"
	"os"
	"syscall"
)

// ReadFactorProposal reads only the protected, fixed adjacent proposal for an
// existing actor/revision. It never accepts a caller-provided path and never
// consumes or deletes material after an uncertain result. Durable account
// revision advancement makes an already used proposal stale.
func (j *AccountJournal) ReadFactorProposal(ctx context.Context, id string, revision uint64) (string, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.failed || ctx == nil || ctx.Err() != nil {
		return "", ErrAuthorityUncertain
	}
	found := false
	for _, a := range j.snapshot.Accounts {
		if a.Operator.ID == id && a.Revision == revision {
			found = true
		}
	}
	if !found {
		return "", ErrAccountConflict
	}
	path := j.file.Name() + ".factor-" + id + ".json"
	if !accountJournalParent(path) {
		return "", ErrConfiguration
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() {
		return "", ErrConfiguration
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", ErrConfiguration
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !os.SameFile(before, after) || !accountJournalFile(f) {
		return "", ErrConfiguration
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4097))
	defer clear(raw)
	if err != nil || len(raw) > 4096 {
		return "", ErrConfiguration
	}
	return parseFactorProposal(raw, j.snapshot.AuthorityID, id, revision)
}

func parseFactorProposal(raw []byte, authorityID, id string, revision uint64) (string, error) {
	if len(raw) > 4096 {
		return "", ErrConfiguration
	}
	var p struct {
		Version          string `json:"version"`
		AuthorityID      string `json:"authorityId"`
		ActorID          string `json:"actorId"`
		ExpectedRevision uint64 `json:"expectedRevision"`
		Secret           string `json:"secret"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil {
		return "", ErrConfiguration
	}
	var compact bytes.Buffer
	if json.Compact(&compact, raw) != nil {
		return "", ErrConfiguration
	}
	defer clear(compact.Bytes())
	canonical, err := json.Marshal(p)
	defer clear(canonical)
	if err != nil || !bytes.Equal(compact.Bytes(), canonical) || p.Version != "tracebolt.operator-factor-proposal.v1" || p.AuthorityID != authorityID || p.ActorID != id || p.ExpectedRevision != revision {
		return "", ErrConfiguration
	}
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	decoded, err := enc.DecodeString(p.Secret)
	defer clear(decoded)
	if err != nil || len(decoded) != 32 || enc.EncodeToString(decoded) != p.Secret {
		return "", ErrConfiguration
	}
	return p.Secret, nil
}
