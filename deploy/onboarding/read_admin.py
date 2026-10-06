#!/usr/bin/env python3
"""Fresh Linux read-admin orchestration, loaded only from verified release bytes.

Inert on import. Existing installers/consent validators own every host operation.
This is a read profile, not arbitrary root access or an existing-host migration.
"""
import hashlib
import json
import os
import re
import stat

PROFILE = "tracebolt.linux-read-admin.v2"
RECEIPT = "/var/lib/tracebolt-agent-installer/read-admin-intent.json"
PHASES = ("inventory", "journal", "socket")
FILES = frozenset([RECEIPT] + [f"/var/lib/tracebolt-agent-installer/read-admin-{phase}.{state}.json"
                  for phase in PHASES for state in ("started", "complete")])
READ_SCOPES = (
    "managed-operations-v3-installed-dpkg-software-services-and-visible-sockets",
    "full-agent-visible-processes-and-mounted-filesystems",
    "agent-visible-complete-known-cached-apt-candidate-rows",
    "agent-visible-linux-hostname-and-interface-addresses",
    "on-demand-current-and-future-supported-exact-system-service-journals",
    "systemd-pid1-local-tcp-udp-socket-owners",
)
LIMITATIONS = {
    "socketProcessAttribution": "Separate privileged metadata-only helper; configuration is not native readiness or a guarantee of complete ownership coverage.",
    "controlledActions": "Not provisioned by this read profile; separately approved exact-target action grants remain separate.",
    "coverage": "Linux namespace/source limits and unsupported package comparisons remain explicit; setup cannot invent missing values.",
    "delivery": "Local configuration confirmation is not proof of first report, actual journal visibility or OS reboot acceptance.",
}


class Rejected(Exception):
    """Fixed safe stages only; never includes child output or private state."""


def require(ok, stage):
    if not ok:
        raise Rejected(stage)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def make_plan(args, manifest, arch):
    require(args.action == "install" and not args.resume and arch == "amd64", "fresh-read-admin-only")
    require(type(manifest["sourceCommit"]) is str and re.fullmatch(r"[0-9a-f]{40}", manifest["sourceCommit"]), "source-revision")
    version = manifest["version"]
    hashes = {role: manifest["assets"][f"tracebolt-{version}-linux-{arch}-{role}"]["sha256"]
              for role in ("agent-service", "enroll-agent", "lan-agent", "socket-owner-reader")}
    hashes["source"] = manifest["assets"][f"tracebolt-{version}-source.tar"]["sha256"]
    require(all(type(h) is str and re.fullmatch(r"[0-9a-f]{64}", h) and h != "0" * 64 for h in hashes.values()), "artifact-hashes")
    return dict(schemaVersion="tracebolt.read-admin-plan.v2", readProfile=PROFILE,
        operation="fresh-install", sourceCommit=manifest["sourceCommit"], release=version,
        architecture=arch, artifacts=hashes, bootstrapSHA256=args.bootstrap_sha256,
        enrollmentOrigin=args.manager_origin, agentOrigin=args.read_admin_agent_origin, invitationId=args.invitation_id,
        transportProfile="http-test" if args.insecure_http_test else "tls",
        scopes=list(READ_SCOPES), controlledActions="not-provisioned", limitations=LIMITATIONS.copy())


def disclosure(plan):
    lines = ["Install Tracebolt read-admin profile", "Enrollment manager: " + plan["enrollmentOrigin"],
        "Inventory and journal destination: " + plan["agentOrigin"],
        "Public bootstrap SHA-256: " + plan["bootstrapSHA256"],
        "Release: " + plan["release"] + " (" + plan["sourceCommit"] + ")",
        "Approve one combined scope: dedicated non-login account, persistent endpoint identity, owned background service, installed dpkg software, services, visible sockets, all visible processes/mounts, all known cached APT candidates, hostname and interface IPv4/IPv6 addresses.",
        "Also approve a separate non-login journal helper and unit-scoped systemd-journal access for on-demand logs from all supported current and future system services. Each request still names one exact service. No kernel/whole-system journal or arbitrary shell is granted.",
        "Also approve the separate socket-owner reader with unit-scoped CAP_SYS_PTRACE: this grants broad process-memory authority. Metadata-only collection is code policy, not an OS read-only confidentiality boundary. It attributes local systemd-PID1 TCP/UDP socket owners; no weaker fallback is permitted.",
        "Process names, mount paths, network addresses and software versions can be sensitive. Journal messages may contain credentials, tokens and personal data; masking is best effort, never secret-free. This data goes only to the bound manager.",
        "Inventory uses the existing capture intervals (full processes/mounts: 60 seconds; full cached APT candidates: six hours). APT remains cached-only; no package refresh or installation is performed. Journal requests remain bounded to one hour within the preceding 24 hours, severity 0-7.",
        "The main agent stays nonroot. The command installs the separate read helpers after your explicit dashboard fingerprint/device approval. Keep this terminal open; hidden invitation entry and device identity approval remain required.",
        "Completed phases are retained. A failure shows its exact phase and keeps identity, counters, pending bytes and journal evidence. Existing installations require their separate upgrade/recovery flow.",
        "Details: " + " ".join(plan["limitations"].values())]
    if plan["transportProfile"] == "http-test":
        lines.append("WARNING: disposable HTTP test only. Invitation/session data, inventory and journal content are readable on the network; the manager can be impersonated, and capability metadata is unauthenticated. This confirmation includes that plaintext-content risk. HTTPS is the default; no TLS downgrade is performed.")
    return "\n".join(lines)


def phrase(plan):
    return "INSTALL READ ADMIN" + (" OVER HTTP" if plan["transportProfile"] == "http-test" else "")


def identity(plan, facts):
    m = facts["manifest"]
    require(m["sourceHash"] == plan["artifacts"]["source"] and
            m["agentHash"] == plan["artifacts"]["lan-agent"] and
            m["enrollHash"] == plan["artifacts"]["enroll-agent"] and
            m["bootstrapHash"] == plan["bootstrapSHA256"] and facts["profile"] == plan["transportProfile"] and
            facts["origin"] == plan["agentOrigin"],
            "installed-release-or-bootstrap-changed")
    return dict(schemaVersion="tracebolt.read-admin-intent.v2", planSHA256=digest(canonical(plan)),
        readProfile=PROFILE, ownerHash=facts["ownerHash"], configHash=facts["configHash"],
        deviceId=facts["deviceId"], managerOrigin=facts["origin"], agentUid=facts["uid"], agentGid=facts["gid"],
        installation=m)


def phase_path(phase, state):
    require(phase in PHASES and state in ("started", "complete"), "fixed-phase")
    return f"/var/lib/tracebolt-agent-installer/read-admin-{phase}.{state}.json"


def phase_record(intent, phase, state):
    return canonical(dict(schemaVersion="tracebolt.read-admin-phase.v2", intentSHA256=digest(canonical(intent)), phase=phase, state=state))


def run(plan, adapter, install, confirm, emit, *, resume=False):
    """One approval, then trusted fixed adapters; all fixtures replace adapters.

    Immutable started/completed receipts are deliberately not an auto-repair log.
    A started phase without completion blocks before any attempted replay.
    """
    result = dict(schemaVersion="tracebolt.read-admin-result.v2", readProfile=PROFILE,
        configurationComplete=False, canceled=False, installation="not_attempted",
        phases={p: "not_attempted" for p in PHASES}, limitations=LIMITATIONS.copy(),
        collectionPerformed=False, nativeAcceptance="not-established")
    bound = None
    socket_attempted = False
    try:
        adapter.preflight(plan, resume)
        emit(disclosure(plan))
        if confirm(phrase(plan)) is not True:
            result["canceled"] = True
            return result
        if resume:
            result["installation"] = "existing_owned_installation"
        else:
            result["installation"] = "uncertain"
            require(install() == 0, "install-or-device-approval-incomplete")
            result["installation"] = "committed"
        bound = identity(plan, adapter.inspect())
        with adapter.lock():
            require(identity(plan, adapter.inspect()) == bound, "installation-changed")
            if resume:
                require(adapter.read(RECEIPT) == canonical(bound), "read-admin-receipt-mismatch")
            else:
                require(adapter.read(RECEIPT) is None, "existing-read-admin-intent")
                adapter.create(RECEIPT, canonical(bound))
        # Reject uncertain final-phase evidence before network checks or earlier
        # phase verification. A lost parent-completion write must not leave an
        # already restored sender active merely because the manager is offline.
        socket_attempted = True
        with adapter.lock():
            require(identity(plan, adapter.inspect()) == bound and adapter.read(RECEIPT) == canonical(bound), "installation-changed")
            started = adapter.read(phase_path("socket", "started"))
            complete = adapter.read(phase_path("socket", "complete"))
            require(started is None or started == phase_record(bound, "socket", "started"), "phase-receipt-mismatch")
            require(complete is None or complete == phase_record(bound, "socket", "complete"), "phase-receipt-mismatch")
            require(complete is None or started is not None, "phase-start-receipt-missing")
            require(started is None or complete is not None, "uncertain-socket-phase-retained")
        socket_attempted = started is not None or complete is not None
        adapter.ready(bound, resume)
        for phase in PHASES:
            socket_attempted = socket_attempted or phase == "socket"
            with adapter.lock():
                require(identity(plan, adapter.inspect()) == bound and adapter.read(RECEIPT) == canonical(bound), "installation-changed")
                started, complete = adapter.read(phase_path(phase, "started")), adapter.read(phase_path(phase, "complete"))
                require(started is None or started == phase_record(bound, phase, "started"), "phase-receipt-mismatch")
                require(complete is None or complete == phase_record(bound, phase, "complete"), "phase-receipt-mismatch")
                require(complete is None or started is not None, "phase-start-receipt-missing")
                require(started is None or complete is not None, "uncertain-" + phase + "-phase-retained")
                if started is None:
                    adapter.create(phase_path(phase, "started"), phase_record(bound, phase, "started"))
            result["phases"][phase] = "verification_pending" if complete else "uncertain"
            adapter.configure(phase, bound, verify_only=complete is not None)
            with adapter.lock():
                require(identity(plan, adapter.inspect()) == bound, "installation-changed-after-" + phase)
                require(adapter.read(phase_path(phase, "started")) == phase_record(bound, phase, "started"), "phase-receipt-changed")
                if complete is None:
                    adapter.create(phase_path(phase, "complete"), phase_record(bound, phase, "complete"))
            result["phases"][phase] = "verified_existing" if complete else "configured_confirmed"
            emit("Read-admin phase confirmed: " + phase + ".")
        result["configurationComplete"] = True
        result["deviceId"] = bound["deviceId"]
    except Exception as exc:
        if socket_attempted and bound is not None:
            try:
                adapter.fail_socket(bound)
            except Exception:
                result["stopUnconfirmed"] = True
        result["failureStage"] = str(exc) if isinstance(exc, (Rejected, *getattr(adapter, "rejection_types", ()))) else "read-admin-phase-incomplete"
        result["recovery"] = "Keep the same installation and all receipts. Inspect the named phase; do not reset identity, remove pending journal evidence or retry an uncertain phase as fresh."
    return result


def real_adapter(s, inventory, amendment, journal_guide, socket_setup, templates, plan, helper_artifact):
    """Composition of existing ownership, scope and journal validators."""
    e = inventory.real_effects(s)
    journal = s.Effects()
    readback = amendment.real_effects(s, {})
    socket_effects = socket_setup.real_effects(s)

    class Adapter:
        rejection_types = (s.Rejected, inventory.Rejected, amendment.Rejected, journal_guide.Rejected, socket_setup.Rejected)

        def inspect(self):
            return inventory.inspect(s, e, templates, inventory.selected_scopes(True))

        def lock(self):
            return e.lock()

        def read(self, path):
            require(path in FILES, "fixed-receipt")
            if e.absent(path):
                return None
            return e.read(path, 16384, 0o600)

        def create(self, path, raw):
            require(path in FILES and type(raw) is bytes and 0 < len(raw) <= 16384, "fixed-receipt")
            # Existing fixed installer directory only. Never creates/adopts it.
            e.protected_dir(s.INSTALLER_DIR)
            require(stat.S_IMODE(e.metadata(s.INSTALLER_DIR).st_mode) == 0o700, "receipt-parent")
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
            try:
                os.fchown(fd, 0, 0)
                os.fchmod(fd, 0o600)
                view = memoryview(raw)
                while view:
                    n = os.write(fd, view)
                    require(n > 0, "receipt-write")
                    view = view[n:]
                os.fsync(fd)
            finally:
                os.close(fd)
            directory = os.open(s.INSTALLER_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            require(self.read(path) == raw, "receipt-readback")

        def preflight(self, plan, resume):
            if resume:
                require(self.read(RECEIPT) is not None, "owned-read-admin-receipt-required")
                bound = identity(plan, self.inspect())
                require(self.read(RECEIPT) == canonical(bound), "read-admin-receipt-mismatch")
            else:
                require(e.absent(s.MANIFEST) and e.absent(s.INSTALLER_DIR), "existing-installation-use-upgrade-or-recovery")
            # No existing helper, policy or pending-journal data may be adopted.
            if not resume:
                require(e.absent(s.CONFIG_DIR), "existing-journal-state-retained")
                socket_setup.fresh_preflight(s, socket_effects)

        def ready(self, bound, resume):
            facts = self.inspect()
            require(identity(plan, facts) == bound, "approved-installation-changed")
            def probe(uid, gid):
                return s.Effects.command(journal, [s.BINARY, "--journal-capabilities"], uid=uid, gid=gid,
                    limit=4096, timeout=5, failure_stage="journal-preview-command-failed")
            socket_manager_compatibility(s, journal, journal_guide, facts)
            journal_guide.compatibility(s, journal, facts, probe)
            if self.read(phase_path("journal", "started")) is None:
                journal_facts, _ = s.preflight(journal, [], templates, all_system_services=True)
                require(s.same_agent(facts, journal_facts), "approved-installation-changed")

        def configure(self, phase, bound, *, verify_only):
            facts = self.inspect()
            require(identity(plan, facts) == bound, "approved-installation-changed")
            if phase == "inventory":
                result = inventory.run(s, e, templates, True, lambda _: True, lambda _: None, verify_only=verify_only, expected_facts=facts)
                require(result["completed"] and not result["canceled"] and "failureStage" not in result and
                        "resumeFailureStage" not in result, "inventory-" + result.get("failureStage", result.get("resumeFailureStage", "validation-or-enable-incomplete")))
            elif phase == "journal":
                if not verify_only:
                    journal_facts, journal_plan = s.preflight(journal, [], templates, all_system_services=True)
                    require(s.same_agent(facts, journal_facts), "approved-installation-changed")
                    result = s.apply(journal, [], templates, s.digest(s.canonical(journal_plan)), True,
                                     facts["profile"] == "http-test", all_system_services=True)
                    require(result["configured"] and "failureStage" not in result, "journal-" + result.get("failureStage", "creation-incomplete"))
                self.verify_journal(bound)
            elif phase == "socket":
                result = socket_setup.configure(s, socket_effects, templates, helper_artifact, facts, digest(canonical(bound)), verify_only=verify_only)
                require(result.get("configured") is True and result.get("configurationOnly") is True, "socket-configuration-unconfirmed")
            else:
                raise Rejected("fixed-phase")

        def fail_socket(self, bound):
            facts = self.inspect()
            require(identity(plan, facts) == bound, "approved-installation-changed")
            socket_setup.fail_closed(s, socket_effects, templates, facts, digest(canonical(bound)))

        def verify_journal(self, bound):
            # Private floor validation needs the stopped nonroot sender. No log
            # query, new grant, helper request or action is made by this check.
            with readback.lock():
                original = self.inspect()
                require(identity(plan, original) == bound, "approved-installation-changed")
                attempted = False
                try:
                    if original["active"]:
                        attempted = True
                        readback.command(["/usr/bin/systemctl", "stop", s.AGENT_UNIT], failure_stage="agent-stop-command-failed")
                    state = readback.status(s.AGENT_UNIT)
                    require(s.owned_unit(state, s.AGENT_UNIT, "inactive") and state["MainPID"] == "0", "readback-agent-not-stopped")
                    facts = amendment.inspect(s, readback, templates)
                    p = facts["policy"]
                    require(p["schemaVersion"] == amendment.V3 and p["serviceAuthorization"] == amendment.ALL_SERVICES and
                            p["enabled"] is True and facts["activity"][s.SOCKET] and facts["enablement"][s.SOCKET] == "enabled",
                            "broad-journal-not-ready")
                    amendment.command(s, readback, facts, "preview", p)
                finally:
                    if attempted:
                        require(identity(plan, self.inspect()) == bound, "readback-resume-identity-changed")
                        # Reuse baseline validation before restoring only prior activity.
                        s.Effects.command(journal, [s.BINARY, "--config", s.CONFIG, "--validate-guided"],
                            uid=original["uid"], gid=original["gid"], failure_stage="journal-preview-command-failed")
                        readback.command(["/usr/bin/systemctl", "start", s.AGENT_UNIT], failure_stage="agent-restart-command-failed")
                        require(s.owned_unit(readback.status(s.AGENT_UNIT), s.AGENT_UNIT, "active"), "readback-resume-unconfirmed")

    return Adapter()


def socket_manager_compatibility(s, e, guide, facts, download=None):
    """Exact public capability, bound to the installed bootstrap origin and CA."""
    raw = e.read(s.BOOTSTRAP, 65536)
    require(digest(raw) == facts["manifest"]["bootstrapHash"], "public-bootstrap-changed")
    bootstrap = guide.strict_json(raw, 65536)
    profile = facts["profile"]
    require(type(bootstrap) is dict and bootstrap.get("profile") == profile and
            bootstrap.get("collectionProfile") == s.PROFILE and bootstrap.get("agentOrigin") == facts["origin"] and
            s.valid_origin(bootstrap.get("enrollmentOrigin"), profile), "socket-manager-capability-origin")
    plaintext = profile == "http-test"
    ca = bootstrap.get("serverCaPem")
    require(ca == "" if plaintext else type(ca) is str and 0 < len(ca) <= 32768, "manager-public-ca")
    try:
        response = (download or guide.fetch)(bootstrap["enrollmentOrigin"] + "/v4/system/capabilities", 2048,
            ca_pem=None if plaintext else ca, plaintext=plaintext)
        value = guide.strict_json(response, 2048)
    except Exception as exc:
        raise Rejected("socket-manager-capability-unavailable-or-upgrade-required") from exc
    expected = dict(schemaVersion="tracebolt.system-manager-capabilities.v1", agentOrigin=facts["origin"],
        systemFrame="tracebolt.agent-system-inventory.v4", socketOwnerSource="tracebolt.socket-owner-source.v1",
        socketOwnerScope="systemd-pid1-local-tcp-udp-socket-owners")
    require(value == expected, "socket-manager-upgrade-required")
    return dict(managerCapabilities=expected, managerAuthenticity=not plaintext)


def run_revoke(adapter, confirm, emit):
    """Explicit maintenance only. Never installs, enrolls or initializes scopes."""
    result = dict(schemaVersion="tracebolt.socket-owner-revoke-result.v1", revoked=False, canceled=False,
                  collectionPerformed=False, nativeAcceptance="not-established")
    bound, approved = None, False
    try:
        bound = adapter.inspect()
        emit("Revoke the socket-owner helper and collection scope for " + bound["deviceId"] +
             " at " + bound["managerOrigin"] + ". Stop and drain participants, disable the root grant, retain a private disabled tombstone and the monotonic floor, and discard only the socket-tagged pending body. Prior agent activity is restored only after confirmed revocation. No renewal or re-enable is provided.")
        if confirm("REVOKE SOCKET OWNERS") is not True:
            result["canceled"] = True
            return result
        approved = True
        adapter.revoke(bound)
        result["revoked"] = True
    except Exception as exc:
        if approved and bound is not None:
            try:
                adapter.fail_socket(bound)
            except Exception as stop_error:
                result["stopUnconfirmed"] = True
                result["helperShutdownUnconfirmed"] = True
                result["containmentFailureStage"] = str(stop_error) if isinstance(stop_error, (Rejected, *getattr(adapter, "rejection_types", ()))) else "socket-owner-containment-unconfirmed"
        result["failureStage"] = str(exc) if isinstance(exc, (Rejected, *getattr(adapter, "rejection_types", ()))) else "socket-owner-revocation-incomplete"
        result["recovery"] = "Keep the disabled/partial policy, tombstone, floor and all receipts. Do not reinstall, renew, rebind or re-enable this scope."
    return result


def real_maintenance(s, inventory, socket_setup, templates, release):
    e = inventory.real_effects(s)
    socket_effects = socket_setup.real_effects(s)

    class Maintenance:
        rejection_types = (s.Rejected, inventory.Rejected, socket_setup.Rejected)

        def inspect(self):
            facts = inventory.inspect(s, e, templates, inventory.selected_scopes(True))
            raw = e.read(RECEIPT, 16384, 0o600)
            bound = inventory.strict_json(raw, 16384)
            require(type(bound) is dict and set(bound) == {"schemaVersion", "planSHA256", "readProfile", "ownerHash", "configHash", "deviceId", "managerOrigin", "agentUid", "agentGid", "installation"} and
                    bound["schemaVersion"] == "tracebolt.read-admin-intent.v2" and bound["readProfile"] == PROFILE and
                    inventory.valid_hash(bound["planSHA256"]) and canonical(bound) == raw, "socket-parent-intent-required")
            current_receipt = bound
            if not e.absent("/var/lib/tracebolt-agent-installer/read-admin-upgrade-current.json"):
                current_receipt = socket_setup.ownership_proof(s, socket_effects, templates, facts, digest(raw))
            require(current_receipt["installation"] == facts["manifest"] and current_receipt["ownerHash"] == facts["ownerHash"] and
                    bound["configHash"] == facts["configHash"] and bound["deviceId"] == facts["deviceId"] and
                    bound["managerOrigin"] == facts["origin"] and bound["agentUid"] == facts["uid"] and bound["agentGid"] == facts["gid"], "socket-parent-identity-changed")
            source = release["assets"]["tracebolt-" + release["version"] + "-source.tar"]["sha256"]
            require(facts["manifest"]["sourceHash"] == source, "socket-maintenance-source-changed")
            for state in ("started", "complete"):
                require(e.read(phase_path("socket", state), 16384, 0o600) == phase_record(bound, "socket", state), "socket-parent-phase-required")
            return bound

        def revoke(self, bound):
            require(self.inspect() == bound, "socket-parent-identity-changed")
            facts = inventory.inspect(s, e, templates, inventory.selected_scopes(True))
            result = socket_setup.revoke(s, socket_effects, templates, facts, digest(canonical(bound)))
            require(result.get("revoked") is True, "socket-revocation-unconfirmed")

        def fail_socket(self, bound):
            require(self.inspect() == bound, "socket-parent-identity-changed")
            facts = inventory.inspect(s, e, templates, inventory.selected_scopes(True))
            socket_setup.fail_closed(s, socket_effects, templates, facts, digest(canonical(bound)), contain_helper=True)

    return Maintenance()
