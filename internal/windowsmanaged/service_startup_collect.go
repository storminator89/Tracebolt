package windowsmanaged

import (
	"context"
	"errors"
	"time"
)

const serviceStartupCollectionBudget = 5 * time.Second

// ServiceStartupReader is a synchronous synthetic seam. It receives only one
// already-inventoried service name. ServiceIndex is assigned by the collector;
// injected readers must return only the finite row contract or a sanitized
// sentinel. Arbitrary reader errors never cross the transport boundary.
type ServiceStartupReader func(context.Context, string) (ServiceStartupRow, error)
type serviceStartupReaderFactory func(context.Context) (ServiceStartupReader, func(), error)

// CollectServiceStartup requires the caller to verify a separate active local
// identity-bound grant before invoking it. services must be the final base rows
// after transport trimming. inventoryAt bounds the original generation; CollectedAt
// captures this later read once and is not atomic with the base inventory.
// Calls are synchronous and cooperatively bounded: an in-flight Windows API
// cannot be forcibly canceled. No service status or PID is queried or joined.
func CollectServiceStartup(ctx context.Context, services []Service, generation, grant string, inventoryAt time.Time) (ServiceStartupSnapshot, error) {
	return collectServiceStartupUsing(ctx, services, generation, grant, inventoryAt, serviceStartupNativeReader, serviceStartupCollectionBudget, time.Now)
}

// CollectServiceStartupWithReader exercises the bounded production collector
// with a synthetic reader, without opening SCM or invoking any native API.
func CollectServiceStartupWithReader(ctx context.Context, services []Service, generation, grant string, inventoryAt time.Time, read ServiceStartupReader) (ServiceStartupSnapshot, error) {
	if read == nil {
		return ServiceStartupSnapshot{}, ErrServiceStartupInvalid
	}
	return CollectServiceStartupWithReaderAndClock(ctx, services, generation, grant, inventoryAt, read, time.Now)
}

// CollectServiceStartupWithReaderAndClock adds a deterministic clock seam for
// source fixtures. The capture must be UTC and not precede inventoryAt; a clock
// regression is rejected rather than silently refreshed or clamped.
func CollectServiceStartupWithReaderAndClock(ctx context.Context, services []Service, generation, grant string, inventoryAt time.Time, read ServiceStartupReader, now func() time.Time) (ServiceStartupSnapshot, error) {
	if read == nil || now == nil {
		return ServiceStartupSnapshot{}, ErrServiceStartupInvalid
	}
	return collectServiceStartupUsing(ctx, services, generation, grant, inventoryAt, func(context.Context) (ServiceStartupReader, func(), error) { return read, func() {}, nil }, serviceStartupCollectionBudget, now)
}

func serviceStartupFailure(quality string) ServiceStartupRow {
	return ServiceStartupRow{StartupQuality: quality, DelayedAutoQuality: quality}
}

func collectServiceStartupUsing(ctx context.Context, services []Service, generation, grant string, inventoryAt time.Time, factory serviceStartupReaderFactory, budget time.Duration, now func() time.Time) (ServiceStartupSnapshot, error) {
	if ctx == nil || factory == nil || now == nil || !validGeneration(generation) || !serviceStartupHex(grant, 32) || !validTime(inventoryAt) {
		return ServiceStartupSnapshot{}, ErrServiceStartupInvalid
	}
	digest, err := ServiceStartupRowsSHA256(services)
	if err != nil {
		return ServiceStartupSnapshot{}, err
	}
	if err := ctx.Err(); err != nil {
		return ServiceStartupSnapshot{}, err
	}
	// Copy rows before a supplied reader runs; the digest and query inputs must
	// continue to describe the same final base array.
	services = append([]Service{}, services...)
	capturedAt := now().UTC()
	if !validTime(capturedAt) || capturedAt.Before(inventoryAt) {
		return ServiceStartupSnapshot{}, ErrServiceStartupInvalid
	}
	s := ServiceStartupSnapshot{SchemaVersion: ServiceStartupSchemaVersion, Scope: ServiceStartupScope, GrantID: grant, GenerationID: generation, ServicesSHA256: digest, CollectedAt: capturedAt, RequestedCount: uint32(len(services)), Rows: []ServiceStartupRow{}}
	if err := ctx.Err(); err != nil {
		return ServiceStartupSnapshot{}, err
	}
	if len(services) == 0 {
		return s, nil
	}
	bounded, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var read ServiceStartupReader
	var closeReader func()
	if bounded.Err() == nil {
		read, closeReader, err = factory(bounded)
	} else {
		err = ErrServiceStartupUnavailable
	}
	if closeReader != nil {
		defer closeReader()
	}
	if err == nil && read == nil {
		err = ErrServiceStartupUnavailable
	}
	for i, service := range services {
		if e := ctx.Err(); e != nil {
			return ServiceStartupSnapshot{}, e
		}
		row := serviceStartupFailure("unavailable")
		switch {
		case bounded.Err() != nil:
			// Internal budget exhaustion is finite per-row unavailability, not
			// caller cancellation and not an apparent observed configuration.
		case err != nil:
			if errors.Is(err, ErrServiceStartupDenied) {
				row = serviceStartupFailure("denied")
			}
		default:
			candidate, e := read(bounded, service.Name)
			if bounded.Err() != nil {
				break
			}
			if e != nil {
				if errors.Is(e, ErrServiceStartupDenied) {
					row = serviceStartupFailure("denied")
				}
			} else {
				if !validServiceStartupRow(candidate) {
					return ServiceStartupSnapshot{}, ErrServiceStartupInvalid
				}
				row = candidate
			}
		}
		row.ServiceIndex = uint32(i)
		s.Rows = append(s.Rows, row)
	}
	if err := ctx.Err(); err != nil {
		return ServiceStartupSnapshot{}, err
	}
	return FitServiceStartupBudget(s, ServiceStartupMaxBytes)
}
