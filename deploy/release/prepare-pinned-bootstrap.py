#!/usr/bin/env python3
"""Verify keyless provenance and assemble a pinned public bootstrap candidate.

No private key, persistent credential, host installation or publication occurs.
The official verification tool is transient and pinned, not installed globally.
"""
import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bootstrap", HERE / "linux-bootstrap.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--source-commit", required=True, help="Independently selected full source/build workflow SHA")
    parser.add_argument("--output", type=Path, required=True, help="New bootstrap source candidate for review")
    args = parser.parse_args()
    bootstrap.require(0 < args.manifest.stat().st_size <= bootstrap.MAX_MANIFEST and 0 < args.bundle.stat().st_size <= bootstrap.MAX_BUNDLE,
                      "Release metadata exceeds its bound.")
    raw, bundle = args.manifest.read_bytes(), args.bundle.read_bytes()
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=bootstrap.unique_object)
    pin = {"version": value["version"], "sourceCommit": args.source_commit, "manifestSHA256": bootstrap.digest(raw), "bundleSHA256": bootstrap.digest(bundle)}
    bootstrap.validate_pin(pin)
    bootstrap.parse_manifest(raw, pin)
    with tempfile.TemporaryDirectory(prefix="tracebolt-release-review-") as temp:
        directory = Path(temp)
        (directory / "manifest.json").write_bytes(raw)
        (directory / "manifest.sigstore.json").write_bytes(bundle)
        verifier = bootstrap.prepare_verifier(directory, "amd64")
        bootstrap.verify_attestation(directory, pin, verifier)
    template = (HERE / "linux-bootstrap.py").read_text()
    bootstrap.require(template.count("RELEASE_PIN = None") == 1, "Bootstrap template is not unconfigured.")
    contents = template.replace("RELEASE_PIN = None", "RELEASE_PIN = " + repr(pin)).encode()
    with bootstrap.open_private(args.output) as stream:
        stream.write(contents)
    print("Keyless workflow provenance verified; public bootstrap candidate prepared.")
    print("Bootstrap SHA-256: " + bootstrap.digest(contents))
    print("Publish assets and pin a separate immutable official bootstrap source commit before enabling the dashboard command.")


if __name__ == "__main__":
    try:
        main()
    except (bootstrap.Rejected, KeyError, OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error) if isinstance(error, bootstrap.Rejected) else "Release provenance could not be verified. No bootstrap was published.") from None
