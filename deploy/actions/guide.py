#!/usr/bin/env python3
"""One manager command, one endpoint command; plan-only unless --apply.

No production adapter is invoked by tests. This file is inert on import.
"""
import argparse
import json
import os
from pathlib import Path
import sys
from common import Rejected, require, canonical, digest, strict_json, protected_read

VERSION = "tracebolt.action-setup-plan.v1"
SOURCE_FILES = ("deploy/actions/guide.py", "deploy/actions/common.py", "deploy/actions/manager.py", "deploy/actions/endpoint.py",
                "deploy/journal/setup.py", "deploy/systemd/tracebolt-agent.service.in",
                "deploy/systemd/tracebolt-action-helper.service.in", "deploy/systemd/tracebolt-action-helper.socket.in")


def verify_source(root):
    manifest = strict_json(protected_read(str(root / "deploy/actions/source-manifest.json")))
    require(set(manifest) == {"schemaVersion", "files"} and manifest["schemaVersion"] == "tracebolt.action-setup-source.v1" and
            set(manifest["files"]) == set(SOURCE_FILES), "setup-source-manifest")
    for name in SOURCE_FILES:
        require(digest(protected_read(str(root / name))) == manifest["files"][name], "setup-source-mismatch")


def make_plan(role, facts):
    require(role in ("manager", "endpoint"), "setup-role")
    plan = {"schemaVersion": VERSION, role: facts}
    plan["planDigest"] = digest(plan)
    return plan


def confirm_and_apply(role, request, adapter, *, apply=False, terminal=False, input_fn=input, output=print):
    facts = adapter.inspect(request)
    plan = make_plan(role, facts)
    output(json.dumps(plan, indent=2, sort_keys=True))
    if facts["state"] == "complete":
        # Existing status is never a new authority-creation approval.
        output("Already configured; verified existing setup without creating authority. Endpoint readiness was not probed.")
        return plan
    if not apply:
        output("Read-only plan. No command key, state, grant, service or socket was created. Run the same command with --apply to review and approve locally.")
        return plan
    require(terminal, "interactive-local-terminal-required")
    output("This grants persistent service-action authority for this exact scope. All listed restart_service operators may approve actions. Setup does not restart the selected managed target.")
    if (facts.get("manager", {}).get("transportProfile") or facts.get("publicBundle", {}).get("transportProfile")) == "disposable-http-test":
        output("HTTP TEST RISK: a stolen plaintext operator session can authorize actions within this local grant.")
    output("Approve the complete displayed host, identity, transport, paths and process changes by typing: APPLY " + plan["planDigest"])
    answer = input_fn()
    require(answer == "APPLY " + plan["planDigest"], "setup-not-approved-no-changes")
    current = adapter.inspect(request)
    require(make_plan(role, current) == plan, "plan-changed-no-changes")
    result = adapter.apply(plan) if role == "manager" else adapter.apply(plan, facts["publicBundle"])
    output(json.dumps(result, indent=2, sort_keys=True))
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="role", required=True)
    manager = sub.add_parser("manager")
    manager.add_argument("--compose-file", required=True)
    manager.add_argument("--project", required=True)
    manager.add_argument("--service", required=True)
    manager.add_argument("--endpoint", required=True)
    manager.add_argument("--lan-ip", help="Existing RFC1918 IPv4 for the disposable HTTP Compose template only")
    endpoint = sub.add_parser("endpoint")
    endpoint.add_argument("--bundle", required=True)
    endpoint.add_argument("--fingerprint", required=True, help="Whole-bundle public digest independently compared with the manager terminal")
    endpoint.add_argument("--review", required=True, help="Protected canonical administrator-reviewed target manifest")
    endpoint.add_argument("--allow-unit", required=True)
    for p in (manager, endpoint):
        p.add_argument("--apply", action="store_true")
        p.add_argument("--ack-http-action-risk", action="store_true")
    args = parser.parse_args(argv)
    try:
        require(os.getresuid() == (0, 0, 0) and os.getresgid() == (0, 0, 0), "root-local-guide-required")
        verify_source(Path(__file__).resolve().parents[2])
        if args.role == "manager":
            from manager import ManagerAdapter
            adapter = ManagerAdapter()
            request = {"composeFile": args.compose_file, "project": args.project, "service": args.service,
                       "endpoint": args.endpoint, "httpAcknowledged": args.ack_http_action_risk, "lanIP": args.lan_ip}
        else:
            from endpoint import EndpointAdapter
            adapter = EndpointAdapter()
            request = {"bundlePath": args.bundle, "bundleFingerprint": args.fingerprint, "reviewPath": args.review,
                       "allowUnit": args.allow_unit, "httpAcknowledged": args.ack_http_action_risk}
        result = confirm_and_apply(args.role, request, adapter, apply=args.apply,
                          terminal=sys.stdin.isatty() and sys.stdout.isatty())
        return 2 if result.get("configured") is False else 0
    except (Exception, KeyboardInterrupt) as exc:
        # No raw paths, command output, private config or key exceptions.
        stage = str(exc) if isinstance(exc, Rejected) else "blocked-or-interrupted"
        print("Action setup " + stage + ". Preserve existing files, keys, receipts and ledgers. Partial changes may remain; do not reset or rerun initialization to repair them.", file=sys.stderr)
        return 2

if __name__ == "__main__":
    raise SystemExit(main())
