//go:build windows && (amd64 || arm64)

package windowsnetworkcontext

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type ipHelperSource struct{}

func Collect(ctx context.Context) (Capture, error) {
	return collectTables(ctx, ipHelperSource{}, func() time.Time { return time.Now().UTC() })
}

func nativeError(e error) error {
	switch {
	case errors.Is(e, windows.ERROR_NOT_ENOUGH_MEMORY), errors.Is(e, windows.ERROR_OUTOFMEMORY):
		return ErrBudget
	case errors.Is(e, windows.ERROR_ACCESS_DENIED):
		return ErrDenied
	case errors.Is(e, windows.ERROR_CALL_NOT_IMPLEMENTED), errors.Is(e, windows.ERROR_NOT_SUPPORTED):
		return ErrUnsupported
	default:
		return ErrUnavailable
	}
}
func numericAddress(s *windows.RawSockaddrInet) (netip.Addr, error) {
	switch s.Family {
	case windows.AF_INET:
		a := (*windows.RawSockaddrInet4)(unsafe.Pointer(s))
		return netip.AddrFrom4(a.Addr), nil
	case windows.AF_INET6:
		a := (*windows.RawSockaddrInet6)(unsafe.Pointer(s))
		v := netip.AddrFrom16(a.Addr)
		if a.Scope_id != 0 {
			v = v.WithZone(strconv.FormatUint(uint64(a.Scope_id), 10))
		}
		return v, nil
	default:
		return netip.Addr{}, ErrInvalid
	}
}
func (ipHelperSource) routes(ctx context.Context) ([]Row, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	var table *windows.MibIpForwardTable2
	e := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table)
	// Windows owns this aggregate allocation; there is no caller-provided size
	// ceiling. Always free synchronously, including any returned error buffer.
	if table != nil {
		defer windows.FreeMibTable(unsafe.Pointer(table))
	}
	if ce := ctx.Err(); ce != nil {
		return nil, ce
	}
	if errors.Is(e, windows.ERROR_NOT_FOUND) {
		return []Row{}, nil
	}
	if e != nil {
		return nil, nativeError(e)
	}
	if table == nil {
		return nil, ErrInvalid
	}
	if table.NumEntries > MaxRoutes {
		return nil, ErrBudget
	}
	out := make([]Row, 0, int(table.NumEntries))
	// Bound the count before forming the slice. No LUID or excluded native field
	// is decoded or copied into the model.
	for i := uint32(0); i < table.NumEntries; i++ {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		r := &unsafe.Slice(&table.Table[0], int(table.NumEntries))[i]
		destination, e := numericAddress(&r.DestinationPrefix.Prefix)
		if e != nil {
			return nil, ErrInvalid
		}
		var scope uint64
		if destination.Zone() != "" {
			scope, _ = strconv.ParseUint(destination.Zone(), 10, 32)
			destination = destination.WithZone("")
		}
		prefix := netip.PrefixFrom(destination, int(r.DestinationPrefix.PrefixLength))
		if !prefix.IsValid() {
			return nil, ErrInvalid
		}
		hop, e := numericAddress(&r.NextHop)
		if e != nil {
			return nil, e
		}
		out = append(out, Row{Kind: "route", InterfaceIndex: r.InterfaceIndex, Route: &Route{Destination: prefix.String(), DestinationScopeID: uint32(scope), NextHop: hop.String(), Metric: r.Metric, Protocol: r.Protocol, Origin: r.Origin}})
	}
	return out, nil
}
func (ipHelperSource) interfaces(ctx context.Context) ([]Row, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	var table *windows.MibIfTable2
	e := windows.GetIfTable2Ex(windows.MibIfTableRaw, &table)
	if table != nil {
		defer windows.FreeMibTable(unsafe.Pointer(table))
	}
	if ce := ctx.Err(); ce != nil {
		return nil, ce
	}
	if e != nil {
		return nil, nativeError(e)
	}
	if table == nil {
		return nil, ErrInvalid
	}
	if table.NumEntries > MaxInterfaces {
		return nil, ErrBudget
	}
	out := make([]Row, 0, int(table.NumEntries))
	for i := uint32(0); i < table.NumEntries; i++ {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		r := &unsafe.Slice(&table.Table[0], int(table.NumEntries))[i]
		// Do not copy the native row: it contains excluded MACs, GUIDs and descriptions.
		alias := nativeAlias(r.Alias[:])
		quality := "unavailable"
		if alias != nil {
			quality = "observed"
		}
		n := func(v uint64) string { return strconv.FormatUint(v, 10) }
		out = append(out, Row{Kind: "interface", InterfaceIndex: r.InterfaceIndex, Counters: &Counters{Alias: alias, AliasQuality: quality, InOctets: n(r.InOctets), OutOctets: n(r.OutOctets), InErrors: n(r.InErrors), OutErrors: n(r.OutErrors), InDiscards: n(r.InDiscards), OutDiscards: n(r.OutDiscards)}})
	}
	return out, nil
}
