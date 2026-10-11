package windowsadapters

import (
	"context"
	"encoding/binary"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// IP_ADAPTER_ADDRESSES offsets for the supported Windows amd64/arm64 ABI.
// Windows compile-time assertions bind these to x/sys/windows declarations.
// Decode only numeric fields, FriendlyName and the DNS/gateway socket lists.
// All native pointers become checked offsets before any byte is inspected.
const adapterMin = 112
const adapterFull = 216
const addressNodeSize = 32

func decodeNative(ctx context.Context, buf []byte, base uint64) Result {
	r := Result{Rows: []Adapter{}, Complete: true}
	if ctx == nil || len(buf) == 0 || len(buf) > MaxNativeBytes || base == 0 {
		return Result{Err: ErrInvalid}
	}
	d := nativeDecoder{buf: buf, base: base, ctx: ctx, seenNodes: map[uint64]bool{}}
	seen := map[uint64]bool{}
	identities := map[[2]uint32]bool{}
	p := base
	for p != 0 {
		if ctx.Err() != nil {
			r.Complete = false
			r.Err = ctx.Err()
			break
		}
		if len(seen) >= MaxObservedRows {
			r.Complete = false
			r.Err = ErrBounds
			break
		}
		b, ok := d.at(p, adapterMin, 8)
		if !ok || seen[p] {
			r.Complete = false
			r.Err = ErrInvalid
			break
		}
		seen[p] = true
		length := int(binary.LittleEndian.Uint32(b))
		if length < adapterMin {
			r.Complete = false
			r.Err = ErrInvalid
			break
		}
		if _, ok = d.at(p, length, 8); !ok {
			r.Complete = false
			r.Err = ErrInvalid
			break
		}
		next := binary.LittleEndian.Uint64(b[8:16])
		// Loopback is outside this scope, even if configured numeric values exist.
		if binary.LittleEndian.Uint32(b[100:104]) == 24 {
			p = next
			continue
		}
		name, valid := d.name(binary.LittleEndian.Uint64(b[72:80]))
		id := [2]uint32{binary.LittleEndian.Uint32(b[4:8]), binary.LittleEndian.Uint32(b[108:112])}
		if !valid || id == [2]uint32{} || identities[id] {
			r.Complete = false
			p = next
			continue
		}
		identities[id] = true
		a := Adapter{IfIndex: id[0], IPv6IfIndex: id[1], Name: name, State: operState(binary.LittleEndian.Uint32(b[104:108])), TxQuality: "unavailable", RxQuality: "unavailable", Gateways: AddressList{"unavailable", []string{}}}
		a.DNSServers = d.addresses(binary.LittleEndian.Uint64(b[48:56]))
		if length >= 200 {
			full, _ := d.at(p, 200, 8)
			a.TxLinkBps, a.TxQuality = linkSpeed(binary.LittleEndian.Uint64(full[184:192]))
			a.RxLinkBps, a.RxQuality = linkSpeed(binary.LittleEndian.Uint64(full[192:200]))
		}
		if length >= adapterFull {
			full, _ := d.at(p, adapterFull, 8)
			a.Gateways = d.addresses(binary.LittleEndian.Uint64(full[208:216]))
		}
		// Count completeness describes adapter coverage. Individual list quality
		// describes missing/truncated address metadata independently.
		r.Rows = append(r.Rows, a)
		p = next
	}
	return r
}
func operState(n uint32) string {
	states := [...]string{"unknown", "up", "down", "testing", "unknown", "dormant", "not-present", "lower-layer-down"}
	if n >= uint32(len(states)) {
		return "unknown"
	}
	return states[n]
}
func linkSpeed(n uint64) (*uint64, string) {
	if n == 0 || n > MaxSafeInteger {
		return nil, "unknown"
	}
	return &n, "observed"
}

type nativeDecoder struct {
	buf       []byte
	base      uint64
	ctx       context.Context
	seenNodes map[uint64]bool
}

func (d *nativeDecoder) at(p uint64, n, alignment int) ([]byte, bool) {
	if p < d.base || n < 0 || alignment <= 0 || p%uint64(alignment) != 0 {
		return nil, false
	}
	o := p - d.base
	if o >= uint64(len(d.buf)) || uint64(n) > uint64(len(d.buf))-o {
		return nil, false
	}
	return d.buf[int(o) : int(o)+n], true
}
func (d *nativeDecoder) name(p uint64) (string, bool) {
	// Bound both UTF-16 work and final UTF-8. Never follow description, suffix,
	// hardware-address or other configuration pointers.
	units := make([]uint16, 0, 96)
	for i := 0; i <= 96; i++ {
		if p > ^uint64(0)-uint64(i*2) {
			return "", false
		}
		b, ok := d.at(p+uint64(i*2), 2, 2)
		if !ok {
			return "", false
		}
		v := binary.LittleEndian.Uint16(b)
		if v == 0 {
			for j := 0; j < len(units); j++ {
				u := units[j]
				if u >= 0xd800 && u <= 0xdbff {
					if j+1 >= len(units) || units[j+1] < 0xdc00 || units[j+1] > 0xdfff {
						return "", false
					}
					j++
				} else if u >= 0xdc00 && u <= 0xdfff {
					return "", false
				}
			}
			s := strings.TrimSpace(string(utf16.Decode(units)))
			return s, validName(s)
		}
		units = append(units, v)
	}
	return "", false
}
func (d *nativeDecoder) addresses(p uint64) AddressList {
	out := AddressList{"observed", []string{}}
	seen := map[string]bool{}
	for p != 0 {
		if d.ctx.Err() != nil || len(d.seenNodes) >= MaxAddressNodes {
			out.Quality = "partial"
			break
		}
		b, ok := d.at(p, addressNodeSize, 8)
		if !ok || d.seenNodes[p] {
			out.Quality = "partial"
			break
		}
		d.seenNodes[p] = true
		n := int(binary.LittleEndian.Uint32(b))
		if n < addressNodeSize {
			out.Quality = "partial"
			break
		}
		if _, ok = d.at(p, n, 8); !ok {
			out.Quality = "partial"
			break
		}
		address, valid := d.socket(binary.LittleEndian.Uint64(b[16:24]), binary.LittleEndian.Uint32(b[24:28]))
		if !valid {
			out.Quality = "partial"
		} else if !seen[address] {
			seen[address] = true
			out.Addresses = append(out.Addresses, address)
		}
		p = binary.LittleEndian.Uint64(b[8:16])
	}
	sort.Strings(out.Addresses)
	if len(out.Addresses) > MaxAddresses {
		out.Addresses = out.Addresses[:MaxAddresses]
		out.Quality = "partial"
	}
	return out
}
func (d *nativeDecoder) socket(p uint64, n uint32) (string, bool) {
	// A length above sockaddr_in6 is unnecessary but may include API padding.
	if n < 2 || n > 128 {
		return "", false
	}
	b, ok := d.at(p, int(n), 2)
	if !ok {
		return "", false
	}
	var a netip.Addr
	switch binary.LittleEndian.Uint16(b) {
	case 2:
		if n < 16 {
			return "", false
		}
		a = netip.AddrFrom4([4]byte(b[4:8]))
	case 23:
		if n < 28 {
			return "", false
		}
		a = netip.AddrFrom16([16]byte(b[8:24]))
		if zone := binary.LittleEndian.Uint32(b[24:28]); zone != 0 {
			a = a.WithZone(strconv.FormatUint(uint64(zone), 10))
		}
	default:
		return "", false
	}
	s := a.String()
	return s, validAddress(s)
}
