// Package windowsmanagedmsiservice owns one separately approved background
// deployment service. Runtime opening cannot install, activate or repair it.
package windowsmanagedmsiservice

import (
	"bytes"
	"context"
	"encoding/json"
	managed "localrmm/internal/windowsmanagedmsi"
	"localrmm/internal/windowsmanagedmsiipc"
	fence "localrmm/internal/windowsmutationfence"
	"localrmm/internal/windowspackage"
	"time"
)

const ScheduledSetupVersion = "tracebolt.windows-managed-msi-service-setup.v4"
const ReusableSetupVersion = "tracebolt.windows-managed-msi-service-setup.v3"
const CoordinatedSetupVersion = "tracebolt.windows-managed-msi-service-setup.v2"
const SetupVersion = "tracebolt.windows-managed-msi-service-setup.v1"

type SetupReceipt struct {
	Version       string                                       `json:"version"`
	PlanDigest    string                                       `json:"planDigest"`
	ConfigDigest  string                                       `json:"configDigest"`
	Registration  managed.SetupRegistration                    `json:"registration"`
	Image         windowspackage.ManagedMSIServiceImageReceipt `json:"image"`
	ServiceMarker string                                       `json:"serviceMarker"`
	Complete      bool                                         `json:"complete"`
}

func Marker(c windowsmanagedmsiipc.Config) string {
	return "Tracebolt managed MSI deployment; config=" + managed.Digest(mustJSON(c))
}
func mustJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func VerifySetup(s managed.Storage, c windowsmanagedmsiipc.Config) (SetupReceipt, error) {
	var r SetupReceipt
	raw, e := s.Read("setup-receipt.json")
	if e != nil || managed.Canonical(raw, &r, managed.MaxRecordBytes) != nil || !(r.Version == SetupVersion && c.Mutation == nil || validPairedSetupVersion(r.Version, c.Grant) && c.Mutation != nil) || !r.Complete || !managed.ValidDigest(r.PlanDigest) || c.Validate() != nil || r.ConfigDigest != managed.Digest(mustJSON(c)) || r.Registration.Validate() != nil || r.Registration.Grant != c.Grant || !bytes.Equal(r.Registration.ExecutorPublicKey, c.ExecutorPublicKey) || r.Image.Validate() != nil || r.Image.Path != c.Executable || r.Image.SHA256 != c.ExecutableDigest || r.ServiceMarker != Marker(c) {
		return r, managed.ErrIntegrity
	}
	return r, nil
}
func CheckExclusive(ctx context.Context) error { return windowspackage.CheckManagedMSIExclusive(ctx) }

func CheckProfile(ctx context.Context, c windowsmanagedmsiipc.Config) error {
	if c.Validate() != nil {
		return managed.ErrAuthority
	}
	if c.Mutation == nil {
		return CheckExclusive(ctx)
	}
	exclusive := windowspackage.CheckCoordinatedMutationExclusive
	if c.Mutation.BackgroundWUA() {
		exclusive = windowspackage.CheckBackgroundMutationExclusive
	}
	if exclusive(ctx) != nil {
		return managed.ErrAuthority
	}
	s, e := fence.Open(ctx, *c.Mutation, fence.ManagedMSI, time.Now)
	if e != nil {
		return e
	}
	defer s.Close()
	return s.Verify(ctx)
}

func validPairedSetupVersion(version string, g managed.Grant) bool {
	switch version {
	case CoordinatedSetupVersion:
		return g.Version == managed.CoordinatedGrantVersion
	case ReusableSetupVersion:
		return g.Version == managed.ReusableGrantVersion
	case ScheduledSetupVersion:
		return g.Scheduled()
	}
	return false
}
