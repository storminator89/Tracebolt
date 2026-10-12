// Package windowsupdateservice is the fresh explicitly consented background
// cached-WUA profile. It cannot adopt a foreground, scheduled or prepared grant.
package windowsupdateservice

import (
	"context"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowspackage"
	"localrmm/internal/windowsupdateipc"
	job "localrmm/internal/windowsupdatejob"
	"localrmm/internal/windowsupdatesetup"
	"time"
)

func Marker(c windowsupdateipc.Config) string { return windowsupdatesetup.ServiceMarker(c) }
func CheckProfile(ctx context.Context, c windowsupdateipc.Config) error {
	if c.Validate() != nil || c.Version != windowsupdateipc.ServiceConfigVersion || c.Mutation == nil || !c.Mutation.BackgroundWUA() || windowspackage.CheckBackgroundMutationExclusive(ctx) != nil {
		return job.ErrAuthority
	}
	s, e := fence.Open(ctx, *c.Mutation, fence.CachedWUA, time.Now)
	if e != nil {
		return e
	}
	defer s.Close()
	return s.Verify(ctx)
}

// VerifyParticipant proves the original shared activation names these exact
// durable local bytes, including after separately approved service activation.
func VerifyParticipant(ctx context.Context, s windowsupdatesetup.Store, c windowsupdateipc.Config) error {
	if c.Validate() != nil || c.Mutation == nil {
		return job.ErrAuthority
	}
	raw, e := s.Read("config.json")
	if e != nil || jobDigest(raw) != windowsupdatesetup.DigestConfig(c) {
		return job.ErrIntegrity
	}
	receipt, e := s.Read("progress.json")
	if e != nil || s.Verify() != nil {
		return job.ErrIntegrity
	}
	m, e := fence.Open(ctx, *c.Mutation, fence.CachedWUA, time.Now)
	if e != nil {
		return e
	}
	defer m.Close()
	return m.VerifyParticipant(ctx, jobDigest(raw), jobDigest(receipt))
}
