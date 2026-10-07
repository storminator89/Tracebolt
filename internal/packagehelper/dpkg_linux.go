//go:build linux

package packagehelper

import (
	"bytes"
	"context"
	"localrmm/internal/actionpermit"
	"localrmm/internal/debianversion"
	"localrmm/internal/packageplan"
	"localrmm/internal/packageupdate"
	"sort"
	"strings"
)

type dpkgPackage struct{ name, architecture, version, multiarch, source, sourceVersion, state, want string }
type dpkgState struct {
	digest, holds string
	packages      map[string]dpkgPackage
}

func parseStatus(raw []byte) (dpkgState, error) {
	s := dpkgState{digest: actionpermit.Digest(raw), packages: map[string]dpkgPackage{}}
	if len(raw) == 0 || len(raw) > 64<<20 || bytes.ContainsAny(raw, "\x00\r") {
		return s, ErrRejected
	}
	holds := []string{}
	for _, paragraph := range strings.Split(string(raw), "\n\n") {
		if strings.TrimSpace(paragraph) == "" {
			continue
		}
		fields := map[string]string{}
		last := ""
		for _, line := range strings.Split(paragraph, "\n") {
			if line == "" {
				continue
			}
			if len(line) > 65536 {
				return s, ErrRejected
			}
			if line[0] == ' ' || line[0] == '\t' {
				if last == "" {
					return s, ErrRejected
				}
				switch last {
				case "Package", "Architecture", "Version", "Status", "Source", "Multi-Arch", "Triggers-Pending", "Triggers-Awaited":
					return s, ErrRejected
				}
				continue
			}
			k, v, ok := strings.Cut(line, ":")
			v = strings.TrimLeft(v, " \t")
			if !ok || k == "" {
				return s, ErrRejected
			}
			if _, seen := fields[k]; seen {
				return s, ErrRejected
			}
			fields[k] = v
			last = k
		}
		state := strings.Fields(fields["Status"])
		if len(state) != 3 || state[1] != "ok" || (state[2] != "installed" && state[2] != "config-files" && state[2] != "not-installed") {
			return s, ErrRejected
		}
		if state[0] != "install" && state[0] != "hold" && state[0] != "deinstall" && state[0] != "purge" && state[0] != "unknown" {
			return s, ErrRejected
		}
		if fields["Triggers-Pending"] != "" || fields["Triggers-Awaited"] != "" {
			return s, ErrRejected
		}
		p := dpkgPackage{name: fields["Package"], architecture: fields["Architecture"], version: fields["Version"], multiarch: fields["Multi-Arch"], source: fields["Package"], sourceVersion: fields["Version"], state: state[2], want: state[0]}
		if p.name == "" || p.architecture == "" {
			return s, ErrRejected
		}
		if p.multiarch == "" {
			p.multiarch = "no"
		}
		if source := fields["Source"]; source != "" {
			v := strings.Fields(source)
			if len(v) == 1 {
				p.source = v[0]
			} else if len(v) == 2 && strings.HasPrefix(v[1], "(") && strings.HasSuffix(v[1], ")") {
				p.source = v[0]
				p.sourceVersion = strings.TrimSuffix(strings.TrimPrefix(v[1], "("), ")")
			} else {
				return s, ErrRejected
			}
		}
		key := p.name + ":" + p.architecture
		if _, exists := s.packages[key]; exists {
			return s, ErrRejected
		}
		s.packages[key] = p
		if p.want == "hold" {
			holds = append(holds, p.name+"\t"+p.architecture+"\n")
		}
	}
	sort.Strings(holds)
	s.holds = actionpermit.Digest([]byte(strings.Join(holds, "")))
	return s, nil
}
func (fs protectedFS) dpkg() (dpkgState, error) {
	names, e := fs.names("/var/lib/dpkg/updates")
	if e != nil || len(names) != 0 {
		return dpkgState{}, ErrRejected
	}
	pending, e := fs.read("/var/lib/dpkg/triggers/Unincorp", 1<<20)
	if e != nil || len(pending) != 0 {
		return dpkgState{}, ErrRejected
	}
	raw, e := fs.read("/var/lib/dpkg/status", 64<<20)
	if e != nil {
		return dpkgState{}, e
	}
	return parseStatus(raw)
}
func validateOld(s dpkgState, p packageplan.Plan) error {
	if s.digest != p.Evidence.DpkgStateDigest || s.digest != p.Evidence.InventoryDigest || s.holds != p.Evidence.HoldsDigest {
		return ErrRejected
	}
	for _, u := range p.Packages {
		v, ok := s.packages[u.Name+":"+u.Architecture]
		if !ok || v.state != "installed" || v.want != "install" || v.version != u.From.Version || v.multiarch != u.From.MultiArch || v.source != u.From.SourcePackage || v.sourceVersion != u.From.SourceVersion {
			return ErrRejected
		}
	}
	return nil
}
func packageRows(p packageplan.Plan, s *dpkgState) []packageupdate.PackageResult {
	out := make([]packageupdate.PackageResult, len(p.Packages))
	for i, u := range p.Packages {
		r := packageupdate.PackageResult{Name: u.Name, Architecture: u.Architecture, ExpectedVersion: u.To.Version, Outcome: "unknown"}
		if s != nil {
			if v, ok := s.packages[u.Name+":"+u.Architecture]; ok && v.state == "installed" {
				if _, e := (debianversion.Comparator{}).Compare(context.Background(), v.version, v.version); e == nil {
					r.ObservedVersion = &v.version
					r.Outcome = "mismatch"
					if v.version == u.To.Version {
						r.Outcome = "verified"
					}
				}
			}
		}
		out[i] = r
	}
	return out
}
