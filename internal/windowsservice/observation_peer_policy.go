package windowsservice

import (
	"encoding/binary"
	"reflect"
	"strings"
)

// This checks an administrator-protected public installation marker and exact
// SCM configuration. The marker hash is NOT a client-measured executable hash.
func observationPublicConfiguration(l Layout, s Snapshot, pid uint32, image string) error {
	if !s.Exists || s.State != Running || pid == 0 || s.ProcessID != pid || !strings.EqualFold(image, l.Executable) || !validServiceSID(s.ServiceSID) {
		return ErrMismatch
	}
	marker := strings.TrimPrefix(s.Configuration.Description, descriptionPrefix)
	if marker == s.Configuration.Description {
		return ErrMismatch
	}
	id, registeredHash, ok := strings.Cut(marker, "; executable-sha256=")
	if !ok || !validHex(id, 16) || !validHex(registeredHash, 32) || !reflect.DeepEqual(s.Configuration, configuration(l, id, registeredHash)) {
		return ErrMismatch
	}
	return nil
}

type observationServiceACE struct {
	SID         string
	Mask        uint32
	Kind, Flags uint8
}

func observationTrustedOwner(sid string) bool {
	return sid == "S-1-5-18" || sid == "S-1-5-32-544" || sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
}
func observationServicePolicy(owner string, aces []observationServiceACE) error {
	if !observationTrustedOwner(owner) || aces == nil || len(aces) > 1024 {
		return ErrUnsafeIdentity
	}
	// Generic write maps to SERVICE_CHANGE_CONFIG. Generic all includes every
	// mutation. Owner/DACL/delete rights also permit replacing service authority.
	const mutations uint32 = 0x40000000 | 0x10000000 | 0x00000002 | 0x00010000 | 0x00040000 | 0x00080000
	for _, a := range aces {
		if a.Mask&^uint32(0xf01f01ff) != 0 {
			return ErrUnsafeIdentity
		}
		if a.Kind != 0 && a.Kind != 1 {
			return ErrUnsafeIdentity
		}
		if a.Flags&8 != 0 {
			continue
		}
		if a.Kind == 0 && a.Mask&mutations != 0 && !observationTrustedOwner(a.SID) {
			return ErrUnsafeIdentity
		}
	}
	return nil
}

// QueryServiceObjectSecurity's success byte count is unspecified. Derive the
// extent from the bounded self-relative SID and ACL fields, never native pointers.
func observationDescriptorExtent(raw []byte) (int, error) {
	if len(raw) < 20 || len(raw) > 8192 || raw[0] != 1 || binary.LittleEndian.Uint16(raw[2:4])&0x8004 != 0x8004 {
		return 0, ErrUnsafeIdentity
	}
	extent := 20
	for _, field := range []int{4, 8, 12, 16} {
		offset := int(binary.LittleEndian.Uint32(raw[field : field+4]))
		if offset == 0 {
			if field == 4 || field == 16 {
				return 0, ErrUnsafeIdentity
			}
			continue
		}
		if offset < 20 || offset%4 != 0 || offset > len(raw)-8 {
			return 0, ErrUnsafeIdentity
		}
		size := 0
		if field == 4 || field == 8 {
			if raw[offset] != 1 || raw[offset+1] > 15 {
				return 0, ErrUnsafeIdentity
			}
			size = 8 + 4*int(raw[offset+1])
		} else {
			if raw[offset] != 2 && raw[offset] != 4 {
				return 0, ErrUnsafeIdentity
			}
			size = int(binary.LittleEndian.Uint16(raw[offset+2 : offset+4]))
			if size < 8 {
				return 0, ErrUnsafeIdentity
			}
		}
		if size > len(raw)-offset {
			return 0, ErrUnsafeIdentity
		}
		if offset+size > extent {
			extent = offset + size
		}
	}
	return extent, nil
}
