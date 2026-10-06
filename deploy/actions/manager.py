"""Supported existing local Docker Compose manager adapter. Inert on import.

A new image must already be deliberately deployed. Never build, pull, change
accounts, repair permissions, or infer an unknown launcher here.
"""
import json
import copy
import os
from pathlib import Path
import re
from common import Rejected, require, canonical, digest, strict_json, protected_read, create_file, run, valid_lan_ip

DOCKER = "/usr/bin/docker"
TOOL = "/tracebolt/action-setup"


def frozen_config(config, service, image, command):
    frozen = copy.deepcopy(config)
    chosen = frozen["services"][service]
    chosen.pop("build", None)
    chosen["image"] = image
    chosen["pull_policy"] = "never"
    chosen["command"] = command
    # Refer to existing named resources; never create or reconcile host scopes.
    for section in ("networks", "volumes"):
        for key, value in frozen.get(section, {}).items():
            frozen[section][key] = {"name": value["name"], "external": True}
    return frozen


def safe_compose_source(source):
    # First support profile is a single local document, not an import resolver.
    # Compose erases include/env_file/extends while normalizing. Reject them in
    # source too; disallow YAML indirection/escapes that could conceal such keys.
    text = source.decode("utf-8")
    require(not re.search(r"\b(?:include|extends|env_file)\b", text) and
            "\\" not in text and "!" not in text and
            not re.search(r"(?m)^\s*[?%]", text) and
            not re.search(r"(?:^|\s)[&*][A-Za-z0-9_-]+", text), "unsupported-compose-source-indirection")



def runtime_digest(container):
    value = {"Config": copy.deepcopy(container["Config"]), "HostConfig": container["HostConfig"],
             "Mounts": container["Mounts"], "Networks": sorted(container["NetworkSettings"]["Networks"])}
    # Only deterministic recreate bookkeeping differs. All user-supplied runtime
    # env, permissions, mounts, resources, exposed ports and network names bind.
    config = value["Config"]
    config.pop("Cmd", None)
    config["Image"] = container["Image"]
    hostname = config.get("Hostname")
    if hostname and container.get("Id", "").startswith(hostname):
        config["Hostname"] = "<docker-generated>"
    labels = config.get("Labels") or {}
    for key in ("com.docker.compose.config-hash", "com.docker.compose.project.config_files", "com.docker.compose.replace"):
        labels.pop(key, None)
    return digest(value)


class DockerEffects:
    def run(self, args, data=None, timeout=30, lan_ip=None):
        require(lan_ip is None or args[0] == "compose", "lan-ip-only-for-compose")
        return run([DOCKER, "--host", "unix:///var/run/docker.sock", *args], data, timeout, lan_ip=lan_ip)
    def read(self, path):
        return protected_read(path)
    def create(self, path, raw):
        create_file(path, raw)
    def absent(self, path):
        return not os.path.lexists(path)


class ManagerAdapter:
    def __init__(self, effects=None):
        self.fx = effects or DockerEffects()

    def compose(self, request, *args, overlay=None, frozen=None):
        base = ["compose", "--project-name", request["project"], "-f", frozen or request["composeFile"]]
        if overlay:
            base += ["-f", overlay]
        return self.fx.run(base + list(args), timeout=90, lan_ip=request["lanIP"])

    def inspect(self, request):
        require(set(request) == {"composeFile", "project", "service", "endpoint", "httpAcknowledged", "lanIP"}, "manager-request")
        require(re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,62}", request["project"]) and
                re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}", request["service"]), "compose-identity")
        require(type(request["httpAcknowledged"]) is bool, "http-acknowledgement")
        require(request["lanIP"] is None or valid_lan_ip(request["lanIP"]), "explicit-private-lan-ip")
        source = self.fx.read(request["composeFile"])
        safe_compose_source(source)
        if not self.fx.absent(request["composeFile"] + ".actions.complete.json"):
            return self.completed(request, source)
        context = strict_json(self.fx.run(["context", "inspect", "default"]))
        require(len(context) == 1 and context[0]["Endpoints"]["docker"]["Host"] == "unix:///var/run/docker.sock",
                "local-docker-required")
        config = strict_json(self.compose(request, "config", "--format", "json"))
        # Only an existing single-service project is supported, without hooks,
        # secrets, includes or external commands hidden in another service.
        require(set(config.get("services", {})) == {request["service"]}, "single-existing-service-required")
        service = config["services"][request["service"]]
        require(set(config) <= {"name", "services", "networks", "volumes"} and
                set(service) <= {"image", "build", "command", "user", "read_only", "cap_drop", "security_opt",
                                 "pids_limit", "mem_limit", "cpus", "restart", "stop_grace_period", "ports", "volumes",
                                 "logging", "networks", "environment", "labels", "hostname", "container_name"} and
                b"$" not in canonical(config), "unsupported-resolved-compose-input")
        require(not any(k in service for k in ("pre_start", "post_start", "pre_stop", "develop", "depends_on", "secrets", "configs", "env_file", "extends")),
                "unsupported-compose-feature")
        ids = self.compose(request, "ps", "--all", "--quiet", request["service"]).decode().split()
        require(len(ids) == 1 and re.fullmatch(r"[a-f0-9]{64}", ids[0]), "one-existing-container-required")
        container = strict_json(self.fx.run(["inspect", ids[0]]))[0]
        require(container["State"]["Running"] is True and not container["State"].get("Restarting") and
                container["Path"] == "/tracebolt/manager" and container["Config"]["Entrypoint"] == ["/tracebolt/manager"],
                "known-running-manager-required")
        labels = container["Config"].get("Labels") or {}
        require(labels.get("com.docker.compose.project") == request["project"] and
                labels.get("com.docker.compose.service") == request["service"] and
                labels.get("com.docker.compose.project.config_files") == request["composeFile"], "compose-launch-binding")
        hashes = self.compose(request, "config", "--hash", request["service"]).decode().split()
        require(len(hashes) == 2 and hashes[0] == request["service"] and
                hashes[1] == labels.get("com.docker.compose.config-hash"), "compose-drift")
        command = container["Config"]["Cmd"]
        require(type(command) is list and len(command) == 4 and command[0] == "--lan-config" and
                command[2] == "--enrollment-config" and command == service.get("command"), "unsupported-manager-command")
        uid = container["Config"]["User"]
        require(re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", uid), "numeric-nonroot-manager-required")
        require(container["HostConfig"]["ReadonlyRootfs"] is True and not container["HostConfig"].get("Privileged"), "manager-container-protection")
        image = container["Image"]
        require(re.fullmatch(r"sha256:[a-f0-9]{64}", image), "immutable-existing-image-required")
        # The exec helper checks actual PID1 real/effective/saved/fs UID/GID.
        plan = strict_json(self.fx.run(["exec", "--user", uid, ids[0], TOOL, "--mode", "plan", "--docker-runtime-probe",
                                       "--lan-config", command[1], "--enrollment-config", command[3], "--endpoint", request["endpoint"]]))
        require(plan["schemaVersion"] == "tracebolt.action-manager-setup.v1" and
                uid == str(plan["uid"]) + ":" + str(plan["gid"]) and plan["endpointId"] == request["endpoint"], "manager-plan-binding")
        require(plan["transportProfile"] != "disposable-http-test" or request["httpAcknowledged"], "separate-http-action-risk-ack-required")
        require(plan["transportProfile"] == "disposable-http-test" or (not request["httpAcknowledged"] and request["lanIP"] is None), "http-ack-or-lan-ip-profile-mismatch")
        state = plan["stateDirectory"]
        mounts = container["Mounts"]
        require(any(m["RW"] and (state == m["Destination"] or state.startswith(m["Destination"] + "/"))
                    for m in mounts), "existing-writable-state-mount-required")
        # Every referenced network/volume already exists, so setup cannot create
        # a new host scope while reconstructing this same known Compose service.
        for network in config.get("networks", {}).values():
            self.fx.run(["network", "inspect", network["name"]])
        for volume in config.get("volumes", {}).values():
            self.fx.run(["volume", "inspect", volume["name"]])
        base = request["composeFile"] + ".actions"
        for suffix in (".intent.json", ".override.json", ".resolved.json", ".bundle.json", ".complete.json"):
            require(self.fx.absent(base + suffix), "existing-setup-evidence-preserved")
        return {"state": "fresh", "request": request, "containerId": ids[0], "image": image, "uid": uid,
                "sourceDigest": digest(source), "composeDigest": digest(config),
                "frozenDigest": digest(frozen_config(config, request["service"], image, ["--lan-config", state + "/service-action-setup/lan.json", "--enrollment-config", plan["enrollmentConfig"]])),
                "runtimeDigest": runtime_digest(container),
                "manager": plan, "outputBase": base,
                "effects": ["stop this manager", "create a separate command key and immutable action domain",
                            "create new LAN config and exact-image launch overlay", "restart this manager only"]}

    def apply(self, plan):
        facts = plan["manager"]
        if facts["state"] == "complete":
            require(self.inspect(facts["request"]) == facts, "completed-setup-changed")
            return {"configured": True, "running": True, "endpointReady": False, "bundlePath": facts["outputBase"] + ".bundle.json", "bundleDigest": facts["publicBundle"]["bundleDigest"]}
        require(self.inspect(facts["request"]) == facts, "manager-plan-changed")
        base, target = facts["outputBase"], facts["containerId"]
        # Host intent precedes stopping; in-container intent precedes keygen/DB.
        self.fx.create(base + ".intent.json", canonical({"schemaVersion": "tracebolt.action-host-intent.v1",
                                                        "planDigest": plan["planDigest"], "facts": facts}))
        try:
            self.fx.run(["stop", "--time", "30", target], timeout=45)
            after = strict_json(self.fx.run(["inspect", target]))[0]
            require(after["State"]["Running"] is False, "manager-stop-unconfirmed")
            public = strict_json(self.fx.run(["run", "--rm", "--pull", "never", "--network", "none", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--user", facts["uid"],
                "--volumes-from", target, "--entrypoint", TOOL, "-i", facts["image"], "--mode", "apply",
                "--confirm-plan", facts["manager"]["digest"]], data=canonical(facts["manager"]), timeout=60))
            command = ["--lan-config", facts["manager"]["stateDirectory"] + "/service-action-setup/lan.json",
                       "--enrollment-config", facts["manager"]["enrollmentConfig"]]
            overlay = {"services": {facts["request"]["service"]: {"image": facts["image"], "pull_policy": "never", "command": command}}}
            # Recheck every external input before publishing the launch bytes.
            # The command below reads only this frozen resolved JSON, never the
            # original Compose file/.env/imports after approval.
            require(digest(self.fx.read(facts["request"]["composeFile"])) == facts["sourceDigest"], "compose-source-changed-before-start")
            resolved = strict_json(self.compose(facts["request"], "config", "--format", "json"))
            require(digest(resolved) == facts["composeDigest"], "compose-changed-before-start")
            frozen = frozen_config(resolved, facts["request"]["service"], facts["image"], command)
            require(digest(frozen) == facts["frozenDigest"], "frozen-launch-plan-changed")
            self.fx.create(base + ".override.json", canonical(overlay))
            self.fx.create(base + ".resolved.json", canonical(frozen))
            self.fx.create(base + ".bundle.json", canonical(public))
            require(digest(strict_json(self.fx.read(base + ".resolved.json"))) == facts["frozenDigest"], "frozen-launch-file-changed")
            self.compose(facts["request"], "up", "--detach", "--no-deps", "--no-build", "--pull", "never",
                         "--wait", "--wait-timeout", "30", facts["request"]["service"], frozen=base + ".resolved.json")
            ids = self.compose(facts["request"], "ps", "--all", "--quiet", facts["request"]["service"], frozen=base + ".resolved.json").decode().split()
            require(len(ids) == 1, "manager-activation-unconfirmed")
            live = strict_json(self.fx.run(["inspect", ids[0]]))[0]
            require(live["State"]["Running"] is True and live["Image"] == facts["image"] and
                    live["Config"]["Cmd"] == command and live["Config"]["User"] == facts["uid"] and
                    runtime_digest(live) == facts["runtimeDigest"], "manager-activation-unconfirmed")
            self.fx.create(base + ".complete.json", canonical({"planDigest": plan["planDigest"], "bundleDigest": public["bundleDigest"], "containerId": ids[0]}))
            return {"configured": True, "running": True, "endpointReady": False, "bundlePath": base + ".bundle.json",
                    "bundleDigest": public["bundleDigest"], "next": "Independently compare this public fingerprint at the selected endpoint."}
        except Exception as exc:
            # No reset, automatic resume, old-config restart or deletion. The
            # container may have been recreated/started before an uncertain reply.
            running = "unknown"
            try:
                candidates = self.compose(facts["request"], "ps", "--all", "--quiet", facts["request"]["service"]).decode().split()
                if len(candidates) == 1:
                    observed = strict_json(self.fx.run(["inspect", candidates[0]]))[0]
                    if observed["Image"] == facts["image"] and observed["Config"]["User"] == facts["uid"]:
                        running = "running" if observed["State"]["Running"] else "stopped"
            except Exception:
                pass
            return {"configured": False, "retainedPartialState": True, "managerState": running,
                    "failureStage": str(exc) if isinstance(exc, Rejected) else "manager-operation-failed",
                    "next": "Inspect retained setup evidence; no automatic reset, resume or restart is authorized."}

    def completed(self, request, source):
        base = request["composeFile"] + ".actions"
        intent = strict_json(self.fx.read(base + ".intent.json"))
        receipt = strict_json(self.fx.read(base + ".complete.json"))
        facts = intent["facts"]
        require(digest(strict_json(self.compose(request, "config", "--format", "json"))) == facts["composeDigest"], "completed-compose-drift")
        require(facts["request"] == request and facts["sourceDigest"] == digest(source) and
                receipt["planDigest"] == intent["planDigest"], "completed-setup-binding")
        overlay = strict_json(self.fx.read(base + ".override.json"))
        require(digest(strict_json(self.fx.read(base + ".resolved.json"))) == facts["frozenDigest"], "completed-frozen-launch-changed")
        command = ["--lan-config", facts["manager"]["stateDirectory"] + "/service-action-setup/lan.json",
                   "--enrollment-config", facts["manager"]["enrollmentConfig"]]
        require(overlay == {"services": {request["service"]: {"image": facts["image"], "pull_policy": "never", "command": command}}}, "completed-overlay-changed")
        ids = self.compose(request, "ps", "--all", "--quiet", request["service"], frozen=base + ".resolved.json").decode().split()
        require(ids == [receipt["containerId"]], "completed-container-changed")
        live = strict_json(self.fx.run(["inspect", ids[0]]))[0]
        require(live["State"]["Running"] is True and live["Image"] == facts["image"] and
                live["Config"]["Cmd"] == command and live["Config"]["User"] == facts["uid"] and
                runtime_digest(live) == facts["runtimeDigest"], "completed-manager-not-running")
        public = strict_json(self.fx.run(["exec", "--user", facts["uid"], ids[0], TOOL, "--mode", "status", "--docker-runtime-probe",
                                         "--lan-config", facts["manager"]["lanConfig"], "--enrollment-config", facts["manager"]["enrollmentConfig"],
                                         "--endpoint", request["endpoint"]]))
        require(public == strict_json(self.fx.read(base + ".bundle.json")) and public["bundleDigest"] == receipt["bundleDigest"], "completed-bundle-changed")
        return {"state": "complete", "request": request, "outputBase": base, "publicBundle": public, "containerId": ids[0]}
