package windowsupdateservice

import (
	"bytes"
	"encoding/json"
	"localrmm/internal/actionpermit"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
	"localrmm/internal/windowsupdatesetup"
)

type Activation struct {
	Version      string                   `json:"version"`
	ConfigDigest string                   `json:"configDigest"`
	Acknowledged bool                     `json:"acknowledged"`
	Manager      job.BackgroundActivation `json:"manager"`
}

func jobDigest(raw []byte) string { return actionpermit.Digest(raw) }
func canonical(raw []byte, out any) error {
	if len(raw) == 0 || len(raw) > job.MaxBytes {
		return job.ErrIntegrity
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(out) != nil {
		return job.ErrIntegrity
	}
	b, _ := json.Marshal(out)
	defer clear(b)
	if !bytes.Equal(b, raw) {
		return job.ErrIntegrity
	}
	return nil
}
func VerifyActivation(s windowsupdatesetup.Store, c windowsupdateipc.Config) error {
	raw, e := s.Read("activation.json")
	var a Activation
	if e != nil || canonical(raw, &a) != nil || a.Version != job.BackgroundActivationVersion || !a.Acknowledged || a.ConfigDigest != windowsupdatesetup.DigestConfig(c) {
		return job.ErrAuthority
	}
	r, e := windowsupdatesetup.Registration(s)
	if e != nil || a.Manager.Verify(r) != nil {
		return job.ErrAuthority
	}
	return nil
}
