#!/usr/bin/env python3
"""Download and verify only the immutable rc.2 native-test inputs; never install.

Called by the explicitly approved hosted upgrade gate as the ordinary runner.
The replacement side remains a separately reviewed current-source build.
"""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import sys

PIN = dict(version="v0.1.0-rc.2", sourceCommit="a6368b0202b1efecdb6214dc34c4302d239854f7",
           manifestSHA256="5eae7faad1e9f3d15881c44d2c8878f5956f5ee5a91ca591a3c9dbba1e650559",
           bundleSHA256="232f7ce69f24d8b9d78265e1b3d1379be5044b89b538341cc6951d31e6459fac")

def main(argv=None):
    parser=argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--directory",required=True)
    args=parser.parse_args(argv)
    if (os.geteuid()==0 or os.environ.get("GITHUB_ACTIONS")!="true" or os.environ.get("RUNNER_ENVIRONMENT")!="github-hosted" or
        os.environ.get("RUNNER_OS")!="Linux" or os.environ.get("TRACEBOLT_APPROVED_READ_ADMIN_UPGRADE")!="true" or
        os.environ.get("TRACEBOLT_READ_ADMIN_SCENARIO")!="complete" or not re.fullmatch(r"[0-9a-f]{40}",os.environ.get("GITHUB_SHA","")) or
        os.environ.get("TRACEBOLT_READ_ADMIN_REVIEWED_SOURCE")!=os.environ.get("GITHUB_SHA")):
        raise SystemExit("Explicit hosted upgrade fixture approval is required; no download started.")
    directory=Path(args.directory)
    if not directory.is_absolute() or str(directory)!=args.directory:
        raise SystemExit("An exact absolute private fixture directory is required.")
    directory.mkdir(mode=0o700)
    os.chmod(directory,0o700)
    spec=importlib.util.spec_from_file_location("verified_prior_release",Path(__file__).with_name("linux-bootstrap.py"))
    bootstrap=importlib.util.module_from_spec(spec);spec.loader.exec_module(bootstrap)
    bootstrap.prepare_release(directory,PIN,"amd64",read_admin=True)
    print("Verified immutable rc.2 manifest, provenance and all amd64/source fixture bytes. No installer was executed.")
    return 0

if __name__=="__main__":
    raise SystemExit(main())
