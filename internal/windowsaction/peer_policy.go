package windowsaction

import (
	"strings"

	"localrmm/internal/enrollmentcrypto"
)

const brokerPublicMarkerPrefix = "Tracebolt Windows action broker; installation="

// This is public SCM attestation, never a client-measured executable hash.
func validBrokerPublicMarker(marker string) error {
	if !strings.HasPrefix(marker, brokerPublicMarkerPrefix) {
		return ErrBinding
	}
	id, digest, ok := strings.Cut(strings.TrimPrefix(marker, brokerPublicMarkerPrefix), "; executable-sha256=")
	if !ok || !enrollmentcrypto.ValidID(id, "broker_") || !ValidDigest("sha256:"+digest) {
		return ErrBinding
	}
	return nil
}

func observationTokenPolicy(user, sid string, session uint32, groups []tokenGroup) error {
	if user != "S-1-5-19" || !validSID(sid) || session != 0 || len(groups) == 0 || len(groups) > 128 {
		return ErrBinding
	}
	found := false
	for _, group := range groups {
		if strings.HasPrefix(group.SID, "S-1-5-80-") && group.SID != sid && group.SID != "S-1-5-80-0" {
			return ErrBinding
		}
		if group.SID == sid {
			// Enabled, owner-capable dedicated service SID, never deny-only.
			if found || group.Attributes&0x4 == 0 || group.Attributes&0x8 == 0 || group.Attributes&0x10 != 0 {
				return ErrBinding
			}
			found = true
		}
	}
	if !found {
		return ErrBinding
	}
	return nil
}
