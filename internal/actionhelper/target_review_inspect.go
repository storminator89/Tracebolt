package actionhelper

import (
	"bytes"
	"context"
	"slices"
	"sort"
	"strings"
)

type setupReviewFile struct {
	raw      []byte
	revision string
}

// Only package-owned production code constructs this adapter. Fixture tests
// supply inert byte snapshots; they never invoke the production adapter.
type setupReviewSource struct {
	run      commandRunner
	read     func(string) (setupReviewFile, error)
	identity func() error
}

func targetListArgs() []string {
	return []string{"--system", "--no-ask-password", "--no-pager", "--no-legend", "--plain", "--type=service", "list-unit-files"}
}

func parseListedServices(raw []byte) ([]string, error) {
	if len(raw) > maxShowBytes || bytes.ContainsAny(raw, "\x00\r") {
		return nil, ErrRejected
	}
	units := []string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		if line == "" && len(raw) == 0 {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || len(fields) > 3 || !listedServiceName(fields[0]) {
			return nil, ErrRejected
		}
		units = append(units, fields[0])
	}
	if len(units) > maxDiscoveryUnits {
		return nil, ErrRejected
	}
	sort.Strings(units)
	if len(slices.Compact(slices.Clone(units))) != len(units) {
		return nil, ErrRejected
	}
	return units, nil
}

func inspectSetupTargetReview(ctx context.Context, source setupReviewSource, architecture string) (SetupTargetReview, error) {
	if ctx == nil || ctx.Err() != nil || source.identity == nil || source.identity() != nil || source.run == nil || source.read == nil {
		return SetupTargetReview{}, ErrRejected
	}
	snapshot := SetupTargetSnapshot{Architecture: architecture, Properties: map[string][]byte{}, Files: map[string][]byte{}, Revisions: map[string]string{}, Unavailable: map[string]string{}}
	totalBytes := 0
	read := func(name string) error {
		if _, ok := snapshot.Files[name]; ok {
			return nil
		}
		if !safeInputPath(name) || ctx.Err() != nil {
			return ErrRejected
		}
		f, err := source.read(name)
		if err != nil || len(f.raw) == 0 || len(f.raw) > maxReviewInputBytes || len(f.raw) > maxReviewTotalBytes-totalBytes {
			return ErrRejected
		}
		totalBytes += len(f.raw)
		snapshot.Files[name] = bytes.Clone(f.raw)
		snapshot.Revisions[name] = f.revision
		return nil
	}
	// Inspect the pinned, fixed client before using it, as the runtime does.
	if read(systemctlPath) != nil {
		return SetupTargetReview{}, ErrUnavailable
	}
	rawList, err := source.run(ctx, targetListArgs())
	if err != nil {
		return SetupTargetReview{}, ErrUnavailable
	}
	snapshot.Units, err = parseListedServices(rawList)
	if err != nil {
		return SetupTargetReview{}, err
	}
	for _, unit := range snapshot.Units {
		if ctx.Err() != nil {
			return SetupTargetReview{}, ctx.Err()
		}
		if !canonicalUnit(unit) || protectedUnit(unit) {
			continue
		}
		raw, err := source.run(ctx, systemctlArgs("show", unit, configurationProperties))
		if err != nil {
			snapshot.Unavailable[unit] = "loaded_properties_unavailable"
			continue
		}
		snapshot.Properties[unit] = bytes.Clone(raw)
		p, err := parseProperties(raw, configurationProperties)
		if err != nil || supportedReviewProperties(unit, p) != "" {
			continue // The pure builder supplies the precise exclusion.
		}
		if err := read(p["FragmentPath"]); err != nil {
			snapshot.Unavailable[unit] = "protected_fragment_unavailable"
			continue
		}
		program, args, reason := parseSimpleService(snapshot.Files[p["FragmentPath"]], p)
		if reason != "" {
			continue
		}
		paths := []string{program}
		for _, arg := range args {
			value := arg
			if _, rhs, ok := strings.Cut(arg, "="); ok {
				value = rhs
			}
			if strings.HasPrefix(value, "/") {
				paths = append(paths, value)
			}
		}
		for _, name := range paths {
			if err := read(name); err != nil {
				snapshot.Unavailable[unit] = "protected_execution_input_unavailable"
				break
			}
		}
	}
	// Two complete observations detect changes during collection. This is not an
	// atomic filesystem/systemd lock. The installer re-inspects after approval;
	// existing runtime checks remain mandatory immediately before each mutation.
	afterList, err := source.run(ctx, targetListArgs())
	afterUnits, parseErr := parseListedServices(afterList)
	if err != nil || parseErr != nil || !slices.Equal(snapshot.Units, afterUnits) {
		return SetupTargetReview{}, ErrRejected
	}
	for _, unit := range snapshot.Units {
		before, ok := snapshot.Properties[unit]
		if !ok {
			continue
		}
		after, err := source.run(ctx, systemctlArgs("show", unit, configurationProperties))
		if err != nil || !bytes.Equal(before, after) {
			return SetupTargetReview{}, ErrRejected
		}
	}
	paths := make([]string, 0, len(snapshot.Files))
	for name := range snapshot.Files {
		paths = append(paths, name)
	}
	sort.Strings(paths)
	for _, name := range paths {
		after, err := source.read(name)
		if err != nil || after.revision != snapshot.Revisions[name] || !bytes.Equal(after.raw, snapshot.Files[name]) {
			return SetupTargetReview{}, ErrRejected
		}
	}
	if ctx.Err() != nil || source.identity() != nil {
		return SetupTargetReview{}, ErrRejected
	}
	return BuildSetupTargetReview(snapshot)
}
