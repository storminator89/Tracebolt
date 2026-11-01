#!/usr/bin/env python3
"""Build unsigned, bounded release candidates from a clean exact source revision.

No signing, GitHub publication, credential creation, or host installation occurs.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bootstrap", HERE / "linux-bootstrap.py")
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)


def run(argv, root, **kwargs):
    return subprocess.run(argv, cwd=root, check=True, **kwargs)


def check_source(root, revision):
    # A checkout/commit can leave the working tree clean. Check both facts at
    # every build boundary; cleanliness alone does not detect revision drift.
    # This is not an atomic source snapshot or a lock against concurrent edits.
    bootstrap.require(not run(["git", "status", "--porcelain", "--untracked-files=all"], root, capture_output=True).stdout and
                      run(["git", "rev-parse", "HEAD"], root, capture_output=True, text=True).stdout.strip() == revision,
                      "Source revision or working tree changed; discard the candidate.")
    # git status can report clean while tracked build inputs differ from HEAD
    # under assume-unchanged or skip-worktree. Refuse such indexes, never clear
    # their flags or rewrite the caller's files to make the check pass.
    indexed = run(["git", "ls-files", "-v", "-z"], root, capture_output=True).stdout
    bootstrap.require(indexed.endswith(b"\0") and
                      all(record.startswith(b"H ") and len(record) > 2 for record in indexed[:-1].split(b"\0")),
                      "Source index flags hide or obscure tracked inputs; discard the candidate.")


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True, help="New directory outside the source checkout")
    args = parser.parse_args()
    bootstrap.require(bootstrap.VERSION.fullmatch(args.version) and len(args.version) <= 64, "Invalid release version.")
    root = HERE.parent.parent
    output = args.output.absolute()
    bootstrap.require(output == output.resolve() and not output.is_relative_to(root) and not output.exists(), "Output must be a new directory outside the checkout.")
    revision = run(["git", "rev-parse", "HEAD"], root, capture_output=True, text=True).stdout.strip()
    bootstrap.require(bootstrap.COMMIT.fullmatch(revision), "A full source revision is required.")
    check_source(root, revision)
    expected_go = next(line.split()[1] for line in (root / "go.mod").read_text().splitlines() if line.startswith("go "))
    probe_env = dict(os.environ, GOTOOLCHAIN="local")
    actual_go = run(["go", "env", "GOVERSION"], root, env=probe_env, capture_output=True, text=True).stdout.strip()
    bootstrap.require(actual_go == "go" + expected_go, "Use the exact Go version declared in go.mod.")
    env = dict(os.environ)
    env.update({"GOTOOLCHAIN": "local", "CGO_ENABLED": "0", "GOOS": "linux", "GOFLAGS": "", "GOWORK": "off", "GOEXPERIMENT": "", "GOAMD64": "v1", "GOARM64": "v8.0"})
    run(["go", "mod", "verify"], root, env=env)
    check_source(root, revision)
    output.mkdir(mode=0o700)
    for arch in bootstrap.ARCHES:
        env["GOARCH"] = arch
        for role in bootstrap.ROLES:
            name = f"tracebolt-{args.version}-linux-{arch}-{role}"
            run(["go", "build", "-buildvcs=true", "-trimpath", "-mod=readonly", "-o", str(output / name), "./cmd/" + role], root, env=env)
            check_source(root, revision)
            os.chmod(output / name, 0o600)
    source = output / f"tracebolt-{args.version}-source.tar"
    with bootstrap.open_private(source) as stream:
        run(["git", "archive", "--format=tar", revision], root, stdout=stream)
    assets = {}
    for name in sorted(bootstrap.asset_names(args.version)):
        path = output / name
        limit = bootstrap.MAX_SOURCE if name.endswith("-source.tar") else bootstrap.MAX_BINARY
        bootstrap.require(0 < path.stat().st_size <= limit, "Built asset exceeds supported bounds.")
        with path.open("rb") as stream:
            checksum = hashlib.file_digest(stream, "sha256").hexdigest()
        assets[name] = {"size": path.stat().st_size, "sha256": checksum}
    # Never leave a completed manifest (or print success) after detected drift.
    # Partial unsigned output remains for local inspection and must be discarded.
    check_source(root, revision)
    manifest = {"schema": bootstrap.SCHEMA, "repository": bootstrap.REPOSITORY, "version": args.version,
                "sourceCommit": revision, "runtimeTargets": list(bootstrap.RUNTIME_TARGETS), "assets": assets}
    with bootstrap.open_private(output / "manifest.json") as stream:
        stream.write((json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode())
    print("Unsigned candidates prepared for offline review. Both amd64 and arm64 were built, not executed. No release or signing key was created.")
    print("Source revision: " + revision)


if __name__ == "__main__":
    try:
        main()
    except (bootstrap.Rejected, OSError, ValueError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error) if isinstance(error, bootstrap.Rejected) else "Unsigned release build failed; inspect the local build result. No release was published.") from None
