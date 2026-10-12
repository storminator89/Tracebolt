//go:build windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"localrmm/internal/actionpermit"
	"localrmm/internal/lanclient"
	"localrmm/internal/windowsservice"
	"localrmm/internal/windowsstate"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
	"localrmm/internal/windowsupdateservice"
	"localrmm/internal/windowsupdatesetup"
)

func nativeBackgroundUpdateActivate(ctx context.Context, digest string, manager job.BackgroundActivation) error {
	root, e := windowsupdateipc.ServiceRootPath()
	if e != nil {
		return e
	}
	s, e := windowsstate.Open(root, windowsupdateipc.ServiceStoreOptions())
	if e != nil {
		return e
	}
	defer s.Close()
	raw, e := s.Read("config.json")
	if e != nil || actionpermit.Digest(raw) != digest {
		return job.ErrAuthority
	}
	c, e := windowsupdateipc.DecodeConfig(raw)
	if e != nil || c.Version != windowsupdateipc.ServiceConfigVersion || windowsupdatesetup.VerifyInstalled(s, c) != nil {
		return job.ErrAuthority
	}
	registration, e := windowsupdatesetup.Registration(s)
	if e != nil || manager.Verify(registration) != nil {
		return job.ErrAuthority
	}
	if _, e = s.Read("activation.json"); !errors.Is(e, fs.ErrNotExist) {
		return job.ErrConflict
	}
	snap, e := windowsservice.InspectOwned(ctx, c.ObserverReceipt)
	if e != nil || snap.State != windowsservice.Running {
		return job.ErrAuthority
	}
	check := func(ctx context.Context) error {
		if s.Verify() != nil || windowsupdateservice.CheckInstalled(ctx, c, false) != nil || windowsupdateservice.CheckProfile(ctx, c) != nil || windowsupdateservice.VerifyParticipant(ctx, s, c) != nil {
			return job.ErrAuthority
		}
		return nil
	}
	authority, e := lanclient.OpenWindowsUpdatePublicAuthority(c, check)
	if e != nil {
		return e
	}
	if e = authority.WithCurrent(ctx, c.Consent.Binding, func(job.Current) error { return nil }); e != nil {
		return e
	}
	a := windowsupdateservice.Activation{Version: job.BackgroundActivationVersion, ConfigDigest: digest, Acknowledged: true, Manager: manager}
	b, _ := json.Marshal(a)
	if e = s.Write("activation.json", b); e != nil {
		return e
	}
	if e = authority.WithCurrent(ctx, c.Consent.Binding, func(job.Current) error { return nil }); e != nil {
		return e
	}
	if e = s.Close(); e != nil {
		return e
	}
	return windowsupdateservice.Activate(ctx, c)
}
