#!/usr/bin/env python3
"""Build deterministic unsigned Windows Setup candidates without executing them.

Uses a temporary source copy. No native installation, service/ACL operation,
credential creation, signing, network bootstrap, or release publication occurs.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("tracebolt_pe_resources", HERE / "pe_resources.py")
resources = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(resources)
require, Rejected = resources.require, resources.Rejected
MAX_INPUT = 128 << 20
MAX_IMAGE = 128 << 20
COPY_ROOTS = ("cmd", "internal")
COPY_FILES = ("go.mod", "go.sum")


def canonical_json(value) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def run(argv, root: Path, **kwargs):
    return subprocess.run(argv, cwd=root, check=True, **kwargs)


def git_source(root: Path, source: str, snapshot: bool) -> str:
    require(resources.COMMIT.fullmatch(source) is not None, "A lowercase full source commit is required.")
    if snapshot:
        return "uncommitted-snapshot"
    top = run(["git", "rev-parse", "--show-toplevel"], root, capture_output=True, text=True).stdout.strip()
    require(Path(top).resolve() == root, "Build from the exact repository root.")
    actual = run(["git", "rev-parse", "HEAD"], root, capture_output=True, text=True).stdout.strip()
    require(actual == source, "Requested source commit does not match the checkout.")
    require(not run(["git", "status", "--porcelain", "--untracked-files=all"], root, capture_output=True).stdout,
            "Builds require a clean checkout, including untracked files; use explicit --source-snapshot only for local source candidates.")
    return "clean-git-commit"


def source_inputs(root: Path) -> tuple[list[dict], dict[str, bytes]]:
    """Freeze only compilation and packaging source, rejecting links and blobs."""
    candidates = []
    for name in COPY_FILES:
        candidates.append(root / name)
    for name in COPY_ROOTS + ("deploy/windows-setup",):
        start = root / name
        require(start.is_dir() and not start.is_symlink(), "Required source directory missing or linked.")
        for current, directories, files in os.walk(start, followlinks=False):
            for entry in directories:
                require(not (Path(current) / entry).is_symlink(), "Source directory links are not accepted.")
            directories[:] = sorted(item for item in directories if item not in ("__pycache__", ".pytest_cache"))
            for entry in sorted(files):
                path = Path(current) / entry
                if entry.endswith((".pyc", ".pyo")):
                    continue
                candidates.append(path)
    entries, contents = [], {}
    total = 0
    for path in sorted(candidates):
        rel = path.relative_to(root).as_posix()
        require(not path.is_symlink() and stat.S_ISREG(path.lstat().st_mode), "Source inputs must be regular nonlinked files.")
        require(path.suffix != ".syso", "Source checkout contains a generated resource object.")
        size = path.stat().st_size
        require(0 <= size <= MAX_INPUT and total + size <= MAX_INPUT, "Source inputs exceed the bounded build contract.")
        raw = path.read_bytes()
        require(len(raw) == size, "Source changed while being copied.")
        total += len(raw)
        entries.append({"path": rel, "size": len(raw), "sha256": sha256(raw)})
        contents[rel] = raw
    return entries, contents


def isolated_environment(arch: str) -> dict:
    require(arch in resources.MACHINES, "Unsupported architecture.")
    env = dict(os.environ)
    env.update({"GOTOOLCHAIN": "local", "GOENV": "off", "CGO_ENABLED": "0",
                "GOOS": "windows", "GOARCH": arch, "GOFLAGS": "", "GOWORK": "off",
                "GOEXPERIMENT": "", "GOAMD64": "v1", "GOARM64": "v8.0"})
    return env


def package_manifest(version: str, source: str, arch: str, service: bytes) -> dict:
    resources.version_parts(version)
    require(resources.COMMIT.fullmatch(source) is not None and arch in resources.MACHINES, "Manifest source/architecture rejected.")
    require(0 < len(service) <= MAX_IMAGE, "Service image exceeds payload bounds.")
    return {"schemaVersion": "tracebolt.windows-setup-package.v1", "version": version,
            "sourceCommit": source, "architecture": arch, "sha256": sha256(service)}


def build(root: Path, output: Path, version: str, source: str, arches: list[str], go: str,
          snapshot: bool = False, rebuild: bool = True) -> dict:
    resources.version_parts(version)
    root = root.resolve()
    output = output.absolute()
    require(output == output.resolve() and not output.is_relative_to(root) and not output.exists(),
            "Output must be a new, canonical directory outside the checkout.")
    require(output.parent.is_dir(), "Output parent directory does not exist.")
    require(arches and len(set(arches)) == len(arches) and all(a in resources.MACHINES for a in arches), "Architecture selection rejected.")
    source_kind = git_source(root, source, snapshot)
    inputs, contents = source_inputs(root)
    input_document = {"schemaVersion": "tracebolt.windows-setup-source-inputs.v1", "files": inputs}
    inputs_raw = canonical_json(input_document)
    expected_go = next(line.split()[1] for line in contents["go.mod"].decode("utf-8").splitlines() if line.startswith("go "))
    env = isolated_environment(arches[0])
    actual_go = run([go, "env", "GOVERSION"], root, env=env, capture_output=True, text=True).stdout.strip()
    require(actual_go == "go" + expected_go, "Use the exact Go version declared in go.mod.")
    host = run([go, "env", "GOHOSTOS", "GOHOSTARCH"], root, env=env, capture_output=True, text=True).stdout.splitlines()
    require(len(host) == 2 and host[0] in ("linux", "windows", "darwin") and host[1] in resources.MACHINES, "Unsupported build host.")
    host_env = dict(env, GOOS=host[0], GOARCH=host[1])
    # Dependency checks are read-only; the build never downloads/runs a separate
    # resource compiler or third-party installer framework.
    run([go, "mod", "verify"], root, env=env)
    with tempfile.TemporaryDirectory(prefix="tracebolt-windows-build-", dir=output.parent) as temporary:
        work = Path(temporary) / "source"
        deliver = Path(temporary) / "artifacts"
        work.mkdir(mode=0o700)
        deliver.mkdir(mode=0o700)
        for rel, raw in contents.items():
            destination = work / rel
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
        assets, checks = {}, {}
        for arch in arches:
            env = isolated_environment(arch)
            command_root = work / "cmd/windows-service"
            payload = command_root / "setup_payload"
            payload.mkdir(exist_ok=True)
            syso = command_root / f"resource_windows_{arch}.syso"
            names = {"service": f"tracebolt-{version}-windows-{arch}-service.exe",
                     "setup": f"Tracebolt-{version}-windows-{arch}-Setup.exe"}
            for setup in (False, True):
                role = "setup" if setup else "service"
                image = deliver / names[role]
                syso.write_bytes(resources.coff_resources(version, source, arch, setup=setup))
                ldflags = "-buildid= -s -w" + (" -H=windowsgui" if setup else "")
                argv = [go, "build", "-trimpath", "-buildvcs=false", "-mod=readonly", "-ldflags=" + ldflags]
                if setup:
                    argv += ["-tags=tracebolt_setup"]
                argv += ["-o", str(image), "./cmd/windows-service"]
                run(argv, work, env=env)
                raw = image.read_bytes()
                require(0 < len(raw) <= MAX_IMAGE, "Candidate image exceeds payload bounds.")
                checks[names[role]] = resources.verify_pe(raw, version, source, arch, setup=setup)
                if rebuild:
                    rebuilt = work / "repeat.exe"
                    second = argv.copy()
                    second[second.index("-o") + 1] = str(rebuilt)
                    run(second, work, env=env)
                    require(rebuilt.read_bytes() == raw, "Repeated build bytes differ; candidate rejected.")
                    rebuilt.unlink()
                if not setup:
                    (payload / "service.exe").write_bytes(raw)
                    manifest_raw = canonical_json(package_manifest(version, source, arch, raw))
                    (payload / "manifest.json").write_bytes(manifest_raw)
                    (deliver / f"setup-package-{arch}.json").write_bytes(manifest_raw)
                    run([go, "run", "-trimpath", "-buildvcs=false", "-mod=readonly",
                         "./deploy/windows-setup/verify-package.go", str(payload / "manifest.json"), str(image)],
                        work, env=host_env)
                    checks[names[role]]["runtimeManifestValidated"] = True
                else:
                    # Embed bytes must be visible verbatim in Go's data section.
                    # This is additional evidence, not a replacement for runtime
                    # strict manifest, size, PE-machine and digest verification.
                    require((payload / "service.exe").read_bytes() in raw and (payload / "manifest.json").read_bytes() in raw,
                            "Setup does not embed the exact reviewed service/manifest payload.")
                checks[names[role]]["repeatBuildIdentical"] = rebuild
            syso.unlink()
        # A changing checkout must never be described as the captured revision.
        after, _ = source_inputs(root)
        require(after == inputs, "Source changed during the build; candidate rejected.")
        git_source(root, source, snapshot)
        (deliver / "source-inputs.json").write_bytes(inputs_raw)
        for path in sorted(deliver.iterdir(), key=lambda p: p.name):
            raw = path.read_bytes()
            assets[path.name] = {"size": len(raw), "sha256": sha256(raw)}
        metadata = {"schemaVersion": "tracebolt.windows-setup-build.v1", "repository": "storminator89/Tracebolt",
                    "version": version, "sourceCommit": source, "sourceKind": source_kind,
                    "sourceCommitRole": "base" if snapshot else "exact", "sourceInputsSHA256": sha256(inputs_raw),
                    "goVersion": actual_go, "architectures": arches, "authenticode": "unsigned",
                    "distributionStatus": "source-candidate-not-released", "nativeExecution": False,
                    "repeatBuildIdentical": rebuild, "assets": assets, "peChecks": checks}
        (deliver / "build-manifest.json").write_bytes(canonical_json(metadata))
        sums = "".join(f"{sha256(p.read_bytes())}  {p.name}\n" for p in sorted(deliver.iterdir(), key=lambda p: p.name))
        (deliver / "SHA256SUMS").write_text(sums, encoding="ascii", newline="\n")
        # Publish locally only after every verification succeeds, leaving no
        # apparently complete output directory behind on failure.
        require(not output.exists(), "Output appeared during the build.")
        deliver.rename(output)
    return metadata


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--arch", action="append", choices=sorted(resources.MACHINES), help="Default: build amd64 and arm64.")
    parser.add_argument("--go", default="go", help="Exact pinned Go toolchain executable.")
    parser.add_argument("--source-snapshot", action="store_true", help="Local candidate only: supplied commit is the base, not a claim that changed source is committed.")
    # Deliberately no signing, publication, install, launch, or skip-verification
    # switch. The two repeated builds are part of each normal candidate build.
    args = parser.parse_args()
    result = build(HERE.parent.parent, args.output, args.version, args.source_commit,
                   args.arch or ["amd64", "arm64"], args.go, snapshot=args.source_snapshot)
    print("Unsigned Setup candidates built and repeated bytes verified; no Setup/service image was run or release published.")
    print("Source kind: " + result["sourceKind"] + "; source input SHA-256: " + result["sourceInputsSHA256"])


if __name__ == "__main__":
    try:
        main()
    except (Rejected, OSError, ValueError, StopIteration, subprocess.SubprocessError) as error:
        raise SystemExit(str(error) if isinstance(error, Rejected) else "Windows Setup build failed. No Setup/service image was run or release published.") from None
