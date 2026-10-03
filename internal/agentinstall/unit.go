package agentinstall

import (
	"strconv"
	"strings"
)

// Unit is fixed, not interpolated from a bootstrap, request body or shell text.
// The dedicated account owns only its private state; installed binaries and unit
// remain root-owned. Read-only collectors must expose denied coverage instead of
// escalating privileges when this sandbox restricts a provider.
const Unit = `[Unit]
Description=Tracebolt read-only endpoint agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300s
StartLimitBurst=5
ConditionPathExists=/var/lib/tracebolt-agent/enrollment/ready.json

[Service]
Type=simple
User=tracebolt-agent
Group=tracebolt-agent
WorkingDirectory=/var/lib/tracebolt-agent
ExecStart=/opt/tracebolt-agent/lan-agent --config /var/lib/tracebolt-agent/enrollment/agent.json --foreground --interval 30s
Restart=on-failure
RestartSec=30s
RestartPreventExitStatus=2
TimeoutStopSec=30s
KillMode=control-group
UMask=0077
NoNewPrivileges=true
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictRealtime=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/lib/tracebolt-agent
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
`

// UnitForAccount binds execution to the recorded numeric identity. The sender
// checks its effective IDs and supplementary groups before private-state access.
func UnitForAccount(uid, gid int) (string, error) {
	if !validAccountID(uid) || !validAccountID(gid) {
		return "", ErrContract
	}
	out := strings.Replace(Unit, "User="+Account+"\n", "User="+strconv.Itoa(uid)+"\n", 1)
	out = strings.Replace(out, "Group="+Account+"\n", "Group="+strconv.Itoa(gid)+"\n", 1)
	out = strings.Replace(out, " --interval 30s\n", " --interval 30s --service-identity "+strconv.Itoa(uid)+":"+strconv.Itoa(gid)+"\n", 1)
	return out, nil
}

func validAccountID(id int) bool { return id > 0 && uint64(id) < uint64(1<<32-1) }
