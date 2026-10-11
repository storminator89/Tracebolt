package windowshardware

import (
	"context"
	"errors"
	"strconv"
	"time"
)

type SystemSource func(context.Context) (System, error)
type FirmwareSource func(context.Context) (Firmware, error)
type ChassisSource func(context.Context) (Chassis, error)
type PowerSource func(context.Context) (Power, error)

func CollectWithSources(ctx context.Context, r Request, system SystemSource, firmware FirmwareSource, power PowerSource, chassis ChassisSource) (Snapshot, error) {
	if ctx == nil {
		return Snapshot{}, ErrInvalid
	}
	if _, e := EncodeConsent(r.Consent, r.SenderBinding); e != nil {
		return Snapshot{}, e
	}
	if !r.Consent.Enabled {
		return Snapshot{}, ErrDisabled
	}
	s := Empty(r, ErrUnavailable.Error())
	if Validate(s) != nil {
		return Snapshot{}, ErrInvalid
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if system != nil {
		v, e := system(ctx)
		if e != nil {
			v = EmptySystem(SafeReason(e))
		}
		if !validSystem(v) {
			v = EmptySystem(ErrMetadata.Error())
		}
		s.System = v
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if firmware != nil {
		v, e := firmware(ctx)
		if e != nil {
			v = EmptyFirmware(SafeReason(e))
		}
		if !validFirmware(v) {
			v = EmptyFirmware(ErrMetadata.Error())
		}
		s.Firmware = v
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if power != nil {
		v, e := power(ctx)
		if e != nil {
			v = EmptyPower(SafeReason(e))
		}
		if !validPower(v) {
			v = EmptyPower(ErrMetadata.Error())
		}
		s.Power = v
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	if chassis != nil {
		v, e := chassis(ctx)
		if e != nil {
			v = EmptyChassis(SafeReason(e))
		}
		if !validChassis(v) {
			v = EmptyChassis(ErrMetadata.Error())
		}
		s.Chassis = v
	}
	if e := ctx.Err(); e != nil {
		return Snapshot{}, e
	}
	return s, Validate(s)
}
func SafeReason(e error) string {
	switch {
	case errors.Is(e, ErrDenied):
		return ErrDenied.Error()
	case errors.Is(e, ErrUnsupported):
		return ErrUnsupported.Error()
	case errors.Is(e, ErrMetadata):
		return ErrMetadata.Error()
	case errors.Is(e, ErrBounds):
		return ErrBounds.Error()
	case errors.Is(e, ErrPartial):
		return ErrPartial.Error()
	case errors.Is(e, context.Canceled), errors.Is(e, context.DeadlineExceeded), errors.Is(e, ErrBudget):
		return ErrBudget.Error()
	default:
		return ErrUnavailable.Error()
	}
}

// Accept only a fully specified valid DMTF timestamp. Unknown/wildcard date parts
// remain unavailable; they are never converted into a guessed calendar date.
func validDMTF(s string) bool {
	if len(s) != 25 || s[:4] == "0000" || s[14] != '.' || (s[21] != '+' && s[21] != '-') {
		return false
	}
	for i, c := range s {
		if i == 14 || i == 21 {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
	}
	_, e := time.Parse("20060102150405.000000", s[:21])
	offset, e2 := strconv.Atoi(s[22:])
	return e == nil && e2 == nil && offset <= 999
}
func observedField(value string, e error, units int) Field {
	if e != nil {
		return emptyField(SafeReason(e))
	}
	if value == "" {
		return Field{Quality: "empty"}
	}
	if !validLabel(value, units) {
		return emptyField(ErrMetadata.Error())
	}
	return Field{&value, "observed"}
}
func finishGroup(fields ...Field) (string, string) {
	for _, f := range fields {
		if f.Quality == "denied" || f.Quality == "unavailable" {
			return "partial", ErrPartial.Error()
		}
	}
	return "observed", ""
}

// Decode only SYSTEM_POWER_STATUS fields; neither battery-health nor any
// firmware/storage API is involved. Sentinel values are never measurements.
func powerStatus(ac, flags, percent uint8, remaining uint32) Power {
	p := EmptyPower(ErrUnavailable.Error())
	p.Quality = "observed"
	p.Reason = ""
	switch ac {
	case 0:
		p.ACLineStatus = "offline"
	case 1:
		p.ACLineStatus = "online"
	}
	switch {
	case flags == 255:
	case flags == 128:
		p.BatteryPresence = "absent"
	case flags & ^uint8(15) == 0:
		p.BatteryPresence = "present"
		p.Charging = "no"
		if flags&8 != 0 {
			p.Charging = "yes"
		}
	}
	if p.BatteryPresence == "present" {
		if percent <= 100 {
			v := percent
			p.BatteryPercent = &v
		}
		if p.ACLineStatus == "offline" && remaining != 0xffffffff {
			v := remaining
			p.EstimatedSeconds = &v
		}
	}
	if !validPower(p) {
		p.Quality = "partial"
		p.Reason = ErrPartial.Error()
	}
	return p
}
