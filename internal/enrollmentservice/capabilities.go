package enrollmentservice

import (
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/model"
)

// profileCapabilities describes the independently selected collection scope,
// not a successful read, current freshness, endpoint health or service install.
// The basic metric bundle cannot describe the separate managed inventories.
// Only the server's immutable binding selects this projection; received labels
// cannot enable it. Dedicated inventory views retain their actual source states.
func profileCapabilities(in []model.Capability, profile string) []model.Capability {
	if !enrollmentcrypto.ManagedCollectionProfile(profile) {
		return in
	}
	out := append([]model.Capability(nil), in...)
	set := func(c model.Capability) {
		for i := range out {
			if out[i].ID == c.ID {
				if out[i].Status == "denied" && c.Status == "limited" {
					c.Status = "denied"
				}
				out[i] = c
				return
			}
		}
		out = append(out, c)
	}
	set(model.Capability{ID: "systemd", Name: "Service inventory", Status: "limited", Detail: "This profile enables read-only service observations. See Inventory for current coverage, source failures and original collection times; selection alone does not prove collection succeeded."})
	set(model.Capability{ID: "journal", Name: "System log metadata", Status: "limited", Detail: "This profile attempts bounded system-journal metadata sampling. The inventory preview shows permission and visibility limits. Raw messages and log bodies are not collected."})
	set(model.Capability{ID: "remote_actions", Name: "Remote actions", Status: "unsupported", Detail: "Remote command execution and remote control are not available. Read-only process and network observations do not grant remote actions."})
	if profile == enrollmentcrypto.CollectionProfileComplete {
		for i := range out {
			if out[i].ID == "os" {
				out[i].Detail = "The OS release comes from the visible /etc/os-release. Optional hostname and interface addresses are separately reported after local opt-in; the device page shows their source coverage and original age."
			}
		}
		set(model.Capability{ID: "systemd", Name: "Service inventory", Status: "limited", Detail: "This profile enables paged systemd runtime and startup-state inventory. Inventory > Services shows actual completeness, failures and original collection times; host permissions and namespace still apply."})
		set(model.Capability{ID: "package_inventory", Name: "Complete dpkg inventory", Status: "limited", Detail: "Inventory > Packages distinguishes complete supported dpkg generations from pending, failed or expired attempts. Complete does not mean every software ecosystem or a vulnerability assessment."})
		set(model.Capability{ID: "socket_inventory", Name: "Local sockets and connections", Status: "limited", Detail: "Inventory > Connections shows local TCP/UDP observations and explicit process-attribution gaps. A local listener does not establish external reachability or firewall exposure."})
	}
	return out
}
