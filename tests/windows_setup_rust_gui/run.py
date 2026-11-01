#!/usr/bin/env python3
"""Manual, inert-hook Windows GUI subset only; never an installer/host grant."""
import sys
if not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("Native GUI fixture requires Python -I -B; no action attempted.")
import argparse
import json
import os
from pathlib import Path
import subprocess
import types

HERE = Path(__file__).resolve().parent
def source_only(name, file):
    path = HERE / file
    if path.is_symlink() or not path.is_file():
        raise SystemExit("Local fixture source unavailable; no action attempted.")
    raw = path.read_bytes()
    if len(raw) > 128 * 1024:
        raise SystemExit("Local fixture source rejected; no action attempted.")
    module = types.ModuleType(name)
    module.__file__ = str(path)
    sys.modules[name] = module
    exec(compile(raw, str(path), "exec"), module.__dict__)
    return module

contract = source_only("rust_gui_contract", "contract.py")

class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, "Native GUI fixture invocation rejected; no action attempted.\n")

def main(argv=None):
    parser = Parser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--execute-gui-fixture", action="store_true")
    parser.add_argument("--case", choices=sorted(contract.CASES))
    parser.add_argument("--source")
    parser.add_argument("--image")
    parser.add_argument("--sha256")
    args = parser.parse_args(argv)
    stage, session = "approval", None
    try:
        contract.authorization(os.name, args.execute_gui_fixture, args.case, args.source, args.sha256, os.environ)
        stage = "source"
        root = HERE.parents[1]
        current = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, check=True).stdout.strip().decode("ascii")
        clean = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=root, capture_output=True, check=True).stdout
        contract.need(current == args.source and not clean, "source")
        native = source_only("rust_gui_windows", "windows.py")
        stage = "launch"
        with native.Session(args.image, args.sha256, args.case) as session:
            checks = contract.drive(session, args.case, contract.Deadline())
            result = session.finish()
            contract.parse_fixture(result, args.case)
        print(json.dumps({"schema": "tracebolt.rust-native-gui-fixture.v1", "status": "passed_inert_gui_subset",
            "case": args.case, "checkoutCommit": current, "imageSHA256": args.sha256,
            "checks": checks, "coverage": contract.COVERAGE, "installerHostActionsAttempted": False}, sort_keys=True))
        return 0
    except contract.Failure as error:
        stage = error.stage
    except Exception:
        pass  # Raw exception/child output, local paths and window text stay private.
    print(json.dumps({"schema": "tracebolt.rust-native-gui-fixture.v1", "status": "not_accepted",
                      "stage": stage, "coverage": contract.COVERAGE, "installerHostActionsAttempted": False}, sort_keys=True))
    return 2

if __name__ == "__main__":
    raise SystemExit(main())
