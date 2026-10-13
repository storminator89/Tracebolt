// Frozen test-only reference from the supplied main25547945447be3189ff6b93f90fe2bb4efc22bdf source.
// Never compiled into a product or evidence probe; uses only synthetic inputs.
package macosinventory

import (
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

func legacyParseHeader(line string) (Interface, error) {
	fields := strings.Fields(line)
	if len(fields) < 4 || !strings.HasSuffix(fields[0], ":") || !strings.HasPrefix(fields[1], "flags=") {
		return Interface{}, ErrMetadata
	}
	name := strings.TrimSuffix(fields[0], ":")
	flagText := strings.TrimPrefix(fields[1], "flags=")
	open := strings.IndexByte(flagText, '<')
	if open < 1 || !strings.HasSuffix(flagText, ">") {
		return Interface{}, ErrMetadata
	}
	flags, e := strconv.ParseUint(flagText[:open], 16, 32)
	if e != nil {
		return Interface{}, ErrMetadata
	}
	var mtu uint64
	count := 0
	for i, s := range fields {
		if s == "mtu" {
			count++
			if i+1 >= len(fields) {
				return Interface{}, ErrMetadata
			}
			mtu, e = decimal(fields[i+1], 32)
			if e != nil {
				return Interface{}, e
			}
		}
	}
	if count != 1 || !token(name, 15, "._-") || mtu == 0 || mtu > 1<<20 {
		return Interface{}, ErrMetadata
	}
	return Interface{Name: name, MTU: uint32(mtu), Up: flags&1 != 0, Running: flags&0x40 != 0, Addresses: []Address{}}, nil
}
func legacyParseAddress(line, name string, ipv6 bool) (Address, error) {
	fields := strings.Fields(line)
	if len(fields) < 4 {
		return Address{}, ErrMetadata
	}
	want := "inet"
	prefixKey := "netmask"
	if ipv6 {
		want = "inet6"
		prefixKey = "prefixlen"
	}
	if fields[0] != want {
		return Address{}, ErrMetadata
	}
	ip, e := netip.ParseAddr(fields[1])
	if e != nil || ip.Is6() != ipv6 || ip.Is4In6() {
		return Address{}, ErrMetadata
	}
	if ip.Zone() != "" && ip.Zone() != name {
		return Address{}, ErrMetadata
	}
	ip = ip.WithZone("")
	count := 0
	var bits uint64
	for i, s := range fields {
		if s != prefixKey {
			continue
		}
		count++
		if i+1 >= len(fields) {
			return Address{}, ErrMetadata
		}
		if ipv6 {
			bits, e = decimal(fields[i+1], 8)
			if e != nil || bits > 128 {
				return Address{}, ErrMetadata
			}
		} else {
			mask := fields[i+1]
			if len(mask) < 3 || len(mask) > 10 || !strings.HasPrefix(mask, "0x") {
				return Address{}, ErrMetadata
			}
			n, e := strconv.ParseUint(mask[2:], 16, 32)
			if e != nil {
				return Address{}, ErrMetadata
			}
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(n))
			ones, width := net.IPMask(b[:]).Size()
			if width != 32 {
				return Address{}, ErrMetadata
			}
			bits = uint64(ones)
		}
	}
	if count != 1 {
		return Address{}, ErrMetadata
	}
	return Address{ip.String(), uint8(bits)}, nil
}

// ParseInterfaces projects only the requested family. Well-formed address
// records of the other family and unselected indented OS metadata are discarded
// without being copied into the result. Unknown top-level records, malformed
// address records and duplicate selected identities fail the source.
func legacyParseInterfaces(raw []byte, ipv6 bool) (Interfaces, error) {
	source := IPv4Source
	if ipv6 {
		source = IPv6Source
	}
	lines, e := sourceLines(raw)
	if e != nil {
		return Interfaces{}, e
	}
	rows := []Interface{}
	for _, line := range lines {
		if line == "" {
			return Interfaces{}, ErrMetadata
		}
		if line[0] != ' ' && line[0] != '\t' {
			if len(rows) >= MaxInterfaces {
				return Interfaces{}, ErrBounds
			}
			r, e := legacyParseHeader(line)
			if e != nil {
				return Interfaces{}, e
			}
			rows = append(rows, r)
			continue
		}
		if len(rows) == 0 {
			return Interfaces{}, ErrMetadata
		}
		trimmed := strings.TrimSpace(line)
		fields := strings.Fields(trimmed)
		if len(fields) == 0 {
			return Interfaces{}, ErrMetadata
		}
		if fields[0] != "inet" && fields[0] != "inet6" {
			continue
		}
		row := &rows[len(rows)-1]
		lineIPv6 := fields[0] == "inet6"
		a, e := legacyParseAddress(trimmed, row.Name, lineIPv6)
		if e != nil {
			return Interfaces{}, e
		}
		// ifconfig emits CLAT46 inet6 metadata even when inet was selected.
		// Validate but discard the other family: it is not evidence for this
		// result, nor does it establish a successful opposite-family read.
		if lineIPv6 != ipv6 {
			continue
		}
		if len(row.Addresses) >= MaxAddresses {
			return Interfaces{}, ErrBounds
		}
		row.Addresses = append(row.Addresses, a)
	}
	v := Interfaces{Status{source, "observed", ""}, rows}
	sortInterfaces(&v)
	if !validInterfaces(v, source, ipv6) {
		return Interfaces{}, ErrMetadata
	}
	return v, nil
}
