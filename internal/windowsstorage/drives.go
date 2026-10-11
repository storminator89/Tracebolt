package windowsstorage

import (
	"context"
	"strings"
)

// Only the assigned 26 drive roots are considered. Native calls cannot accept
// caller-selected paths; mapped network drives are skipped before GUID lookup.
type driveAPI interface {
	mask() (uint32, error)
	driveType(byte) (uint32, error)
	volume(byte) (string, error)
}

func collectDrives(ctx context.Context, a driveAPI) (Drives, error) {
	if ctx == nil || a == nil {
		return Drives{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return Drives{}, e
	}
	mask, e := a.mask()
	if e != nil {
		return Drives{}, e
	}
	if mask & ^uint32((1<<26)-1) != 0 {
		return Drives{}, ErrMetadata
	}
	s := Drives{Quality: "observed", Rows: []Drive{}, CountExact: true, Complete: true}
	for i := 0; i < 26; i++ {
		if mask&(1<<i) == 0 {
			continue
		}
		if e := ctx.Err(); e != nil {
			return Drives{}, e
		}
		letter := byte('A' + i)
		typ, e := a.driveType(letter)
		if e == nil && typ == 4 {
			continue
		}
		r := Drive{Letter: string(letter) + ":", DriveType: "unknown", Quality: "unavailable", Reason: ErrUnsupported.Error()}
		switch typ {
		case 2:
			r.DriveType = "removable"
		case 3:
			r.DriveType = "fixed"
		case 5:
			r.DriveType = "cdrom"
		case 6:
			r.DriveType = "ramdisk"
		}
		if e != nil {
			r.Reason = SafeReason(e)
		} else if r.DriveType != "unknown" {
			guid, err := a.volume(letter)
			if err != nil {
				r.Reason = SafeReason(err)
			} else {
				guid = strings.ToLower(guid)
				guid = strings.Replace(guid, "volume", "Volume", 1)
				if !ValidVolumeGUID(guid) {
					r.Reason = ErrMetadata.Error()
				} else {
					r.Quality = "observed"
					r.Reason = ""
					r.VolumeGUID = &guid
				}
			}
		}
		if r.Reason == ErrDenied.Error() {
			r.Quality = "denied"
		}
		if r.Quality != "observed" {
			s.Quality = "partial"
			s.Reason = ErrPartial.Error()
		}
		s.Rows = append(s.Rows, r)
		s.ObservedCount++
	}
	return s, nil
}
