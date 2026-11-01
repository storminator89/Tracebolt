#!/usr/bin/env python3
"""One PR201-only TLS GUI case with memory-only hooks; never installer acceptance."""
import sys
if not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Inert GUI CI requires Python -I -B; no action attempted.")
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import types

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
PLATFORM = os.name

# Reuse the unchanged manual source loader, not its CI-forbidden entry point.
path = HERE / "run.py"
if path.is_symlink() or not path.is_file() or path.stat().st_size > 128 * 1024:
    raise SystemExit("Local inert GUI source unavailable; no action attempted.")
manual = types.ModuleType("rust_gui_manual")
manual.__file__ = str(path)
sys.modules[manual.__name__] = manual
exec(compile(path.read_bytes(), str(path), "exec"), manual.__dict__)
contract = manual.contract
policy = manual.source_only("rust_gui_ci_policy", "ci_policy.py")
provenance = manual.source_only("rust_gui_ci_provenance", "ci_provenance.py")

def read_build(directory, state):
    manifest = directory / "build.json"
    contract.need(manifest.is_file() and not manifest.is_symlink() and manifest.stat().st_size <= 65536, "provenance")
    try:
        value = json.loads(manifest.read_bytes(), object_pairs_hook=contract.unique_object)
    except (ValueError, UnicodeError, contract.Failure):
        raise contract.Failure("provenance") from None
    value = policy.validate_build(value, state, provenance.TAGS.split(","), provenance.PROJECT_DEPENDENCIES)
    image = directory / policy.IMAGE
    contract.need(image.is_file() and not image.is_symlink() and image.stat().st_size == value["image"]["size"], "provenance")
    raw = image.read_bytes()
    contract.need(len(raw) == value["image"]["size"] and hashlib.sha256(raw).hexdigest() == value["image"]["sha256"], "provenance")
    contract.need(state["sourceCommit"].encode() in raw, "provenance")
    contract.need(provenance.inspect_pe(raw) == value["pe"], "provenance")
    go = shutil.which("go.exe")
    contract.need(go is not None and Path(go).is_absolute() and not Path(go).resolve().is_relative_to(ROOT.resolve()), "provenance")
    tool = Path(go)
    contract.need(tool.is_file() and not tool.is_symlink() and 512 <= tool.stat().st_size <= 128 * 1024 * 1024, "provenance")
    contract.need(hashlib.sha256(tool.read_bytes()).hexdigest() == value["tools"]["goSHA256"], "provenance")
    tool_env = dict(os.environ, APPDATA=str(directory / "appdata"), LOCALAPPDATA=str(directory / "localappdata"), GOENV="off", GOTOOLCHAIN="local")
    info = subprocess.run([str(tool), "version", "-m", str(image)], cwd=ROOT, env=tool_env, capture_output=True, check=True, timeout=15).stdout
    contract.need(provenance.inspect_go_build_info(info, state["sourceCommit"]) == value["goBuild"], "provenance")
    return value

def session(image, digest):
    native = manual.source_only("rust_gui_windows", "windows.py")
    class TLSCISession(native.Session):
        def _command(self):
            return [self.image, "-test.run=^TestRustNativeGUITLSCI$", "-test.count=1", "-test.timeout=80s"]
    return TLSCISession(str(image), digest, "tls")

def main(argv=None):
    parser = manual.Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--execute-github-tls-fixture", action="store_true")
    parser.add_argument("--source")
    args = parser.parse_args(argv)
    stage = "approval"
    try:
        env = policy.authorization(PLATFORM, args.execute_github_tls_fixture, args.source, os.environ)
        stage = "source"
        state = policy.source_state(ROOT, args.source, env)
        directory = policy.output_directory(env)
        stage = "provenance"
        build = read_build(directory, state)
        stage = "launch"
        with session(directory / policy.IMAGE, build["image"]["sha256"]) as ui:
            checks = contract.drive(ui, "tls", contract.Deadline())
            raw = ui.finish()
            contract.parse_fixture(raw, "tls")
            policy.parse_source_ack(raw, args.source)
        contract.need(policy.source_state(ROOT, args.source, env) == state, "source")
        print(json.dumps({"schema": "tracebolt.rust-native-gui-ci.v1", "status": "passed_tls_inert_gui_ci_subset",
            "case": "tls", **state, "prHeadCommit": env["TRACEBOLT_RUST_GUI_CI_HEAD"],
            "runID": env["GITHUB_RUN_ID"], "runAttempt": env["GITHUB_RUN_ATTEMPT"],
            "imageSHA256": build["image"]["sha256"], "rustArchiveSHA256": build["rustArchive"]["sha256"],
            "checks": checks, "coverage": contract.COVERAGE, "installerHostActionsAttempted": False}, sort_keys=True))
        return 0
    except contract.Failure as error:
        stage = error.stage
    except Exception:
        pass  # Never export raw process output, errors, paths or window text.
    print(json.dumps({"schema": "tracebolt.rust-native-gui-ci.v1", "status": "not_accepted",
                      "case": "tls", "stage": stage, "coverage": contract.COVERAGE,
                      "installerHostActionsAttempted": False}, sort_keys=True))
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
