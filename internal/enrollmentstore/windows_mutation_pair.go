package enrollmentstore

import (
	"encoding/json"
	"localrmm/internal/actionpermit"
	managed "localrmm/internal/windowsmanagedmsi"
	job "localrmm/internal/windowsupdatejob"
)

// A matching plan label alone cannot bypass the old mutual exclusion. Both
// fresh grants bind the exact independent peer binding and original identity.
func coordinatedWindowsMutationPair(m managed.Grant, w job.Consent) bool {
	if m.Validate() != nil || w.Validate() != nil || (m.Version != managed.CoordinatedGrantVersion && m.Version != managed.ReusableGrantVersion) || (w.Version != job.CoordinatedConsentVersion && !w.Background()) || w.Background() && m.Version != managed.ReusableGrantVersion || m.MutationPlanDigest != w.MutationPlanDigest || m.Binding.ManagerID != w.Binding.ManagerID || m.Binding.DeviceID != w.Binding.DeviceID || m.Binding.IncarnationDigest != w.Binding.IncarnationDigest {
		return false
	}
	mb, _ := json.Marshal(m.Binding)
	wb, _ := json.Marshal(w.Binding)
	return m.PeerBindingDigest == actionpermit.Digest(wb) && w.PeerBindingDigest == actionpermit.Digest(mb)
}
