package enrollmentservice

import (
	"localrmm/internal/enrollmentcrypto"
	"localrmm/internal/model"
)

// profileCapabilities describes the independently selected collection scope,
// not a successful read, current freshness, endpoint health or service install.
// The basic metric bundle cannot describe the separate managed inventories.
// The manager-only scope status is informational and is rejected in endpoint
// observation bundles. It must not be presented as observed success or failure.
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
				if out[i].Status == "denied" && c.Status == "scope" {
					c.Status = "denied"
				}
				out[i] = c
				return
			}
		}
		out = append(out, c)
	}
	set(model.Capability{ID: "systemd", Name: "Service inventory", Status: "scope", Detail: "This profile enables read-only service observations. See Inventory for current coverage, source failures and original collection times; selection alone does not prove collection succeeded."})
	set(model.Capability{ID: "journal", Name: "System log metadata", Status: "scope", Detail: "This profile attempts bounded system-journal metadata sampling. The inventory preview shows permission and visibility limits. Raw messages and log bodies are not collected."})
	set(model.Capability{ID: "remote_actions", Name: "Remote actions", Status: "unsupported", Detail: "Remote command execution and remote control are not available. Read-only process and network observations do not grant remote actions."})
	if profile == enrollmentcrypto.CollectionProfileComplete {
		set(model.Capability{ID: "journal", Name: "System log metadata", Status: "scope", Detail: "The automatic inventory preview samples journal metadata only and excludes message bodies. Its permission result is separate from the optional on-demand Logs helper."})
		set(model.Capability{ID: "journal_content", Name: "On-demand service logs", Status: "scope", Detail: "Logs can request a bounded service/time/severity snapshot only after a compatible endpoint upgrade and separate local helper/content permission. Messages may contain secrets despite masking. Request status and source coverage are shown in Logs; this capability does not establish a configured helper or successful access."})
		for i := range out {
			if out[i].ID == "os" {
				out[i].Detail = "The OS release comes from the visible /etc/os-release. Optional hostname and interface addresses are separately reported after local opt-in; the device page shows their source coverage and original age."
			}
		}
		set(model.Capability{ID: "systemd", Name: "Service inventory", Status: "scope", Detail: "This profile enables paged systemd runtime and startup-state inventory. Inventory > Services shows actual completeness, failures and original collection times; host permissions and namespace still apply."})
		set(model.Capability{ID: "complete_process_inventory", Name: "Complete visible process inventory", Status: "scope", Detail: "After a compatible endpoint upgrade and explicit local complete-overview consent, Inventory > Processes pages every successfully enumerated process in the agent's Linux namespace. Names may be sensitive; field permissions and resource failures remain explicit. This does not establish local consent or successful collection."})
		set(model.Capability{ID: "complete_mount_inventory", Name: "Complete visible mount inventory", Status: "scope", Detail: "After a compatible endpoint upgrade and explicit local complete-overview consent, Inventory > Mounts pages all successfully enumerated mounted filesystems in the agent's namespace. Local, memory, virtual and remote mounts remain distinct; capacity may be unavailable. This is not a physical disk or host-namespace coverage claim."})
		set(model.Capability{ID: "package_inventory", Name: "Complete dpkg inventory", Status: "scope", Detail: "Inventory > Packages distinguishes complete supported dpkg generations from pending, failed or expired attempts. Complete does not mean every software ecosystem or a vulnerability assessment."})
		set(model.Capability{ID: "socket_inventory", Name: "Local sockets and connections", Status: "scope", Detail: "Inventory > Connections shows local TCP/UDP observations and explicit process-attribution gaps. A local listener does not establish external reachability or firewall exposure."})
		set(model.Capability{ID: "socket_owner_metadata", Name: "Connection process attribution", Status: "scope", Detail: "Read-admin configures the separate socket-owner helper. Current helper provenance establishes a reported collection, not complete attribution of every connection; missing owners and per-row source failures remain explicit in Inventory > Connections."})
	}
	return out
}
