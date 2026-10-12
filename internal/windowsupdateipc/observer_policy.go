package windowsupdateipc

import (
	"strconv"
	"strings"
)

type tokenGroup struct {
	SID        string
	Attributes uint32
}

func validSID(s string) bool {
	parts := strings.Split(s, "-")
	if len(parts) != 9 || strings.Join(parts[:4], "-") != "S-1-5-80" {
		return false
	}
	nonzero := false
	for _, p := range parts[4:] {
		n, e := strconv.ParseUint(p, 10, 32)
		if e != nil || strconv.FormatUint(n, 10) != p {
			return false
		}
		nonzero = nonzero || n != 0
	}
	return nonzero
}

func observationTokenPolicy(user, sid string, session uint32, groups []tokenGroup) error {
	if user != "S-1-5-19" || !validSID(sid) || session != 0 || len(groups) == 0 || len(groups) > 128 {
		return ErrPeer
	}
	found := false
	for _, group := range groups {
		if strings.HasPrefix(group.SID, "S-1-5-80-") && group.SID != sid && group.SID != "S-1-5-80-0" {
			return ErrPeer
		}
		if group.SID == sid {
			// Enabled, owner-capable dedicated service SID, never deny-only.
			if found || group.Attributes&0x4 == 0 || group.Attributes&0x8 == 0 || group.Attributes&0x10 != 0 {
				return ErrPeer
			}
			found = true
		}
	}
	if !found {
		return ErrPeer
	}
	return nil
}
