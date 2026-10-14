#!/usr/bin/env python3
"""Build unsigned, deterministic per-architecture macOS service test packages.

This prepares review bytes only. It never executes a Darwin binary, installs,
enrolls, signs, notarizes, or publishes anything.
"""
from __future__ import annotations

import gzip
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import tempfile


HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("macos_foreground_builder", HERE / "build-foreground-candidate.py")
base = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(base)

ROOT = HERE.parents[1]
SCHEMA = "tracebolt.macos-service-test-package.v1"
PAYLOAD_SCHEMA = "tracebolt.macos-service-test-payload.v1"
ROLES = {"enroll-agent": "./cmd/enroll-agent", "macos-agent": "./cmd/macos-agent",
         "macos-agent-service": "./cmd/macos-agent-service",
         "macos-package-prepare": "./deploy/macos-release/prepare"}
PAYLOAD_STATIC = {"TESTING.md": "docs/macos-test-package.md"}
MAX_PACKAGE = 384 << 20
MAX_DOCUMENT = 128 << 10
MAX_MANIFEST = 16 << 10


def role_path(role: str) -> str:
    return "localrmm/" + ROLES[role].removeprefix("./")


def checked_binary(path: Path, arch: str, role: str, root: Path, env: dict,
                   pinned_go: str) -> tuple[int, str]:
    with path.open("rb") as stream:
        header = stream.read(16)
    base.require(len(header) == 16 and header[:4] == base.MACHO_MAGIC
                 and int.from_bytes(header[4:8], "little") == base.MACHO_CPU[arch]
                 and int.from_bytes(header[12:16], "little") == 2,
                 "A package binary is not a thin Mach-O executable for its architecture.")
    lines = base.output_text(["go", "version", "-m", str(path)], root, env=env).splitlines()
    base.require(lines and lines[0] == f"{path}: go{pinned_go}",
                 "Package binary Go version differs from reviewed source.")
    paths = [line.strip().split("\t", 1)[1] for line in lines if line.strip().startswith("path\t")]
    modules = [line.strip().split("\t", 2)[1] for line in lines if line.strip().startswith("mod\t")]
    settings: dict[str, str] = {}
    for line in lines:
        fields = line.strip().split("\t", 1)
        if len(fields) == 2 and fields[0] == "build" and "=" in fields[1]:
            key, value = fields[1].split("=", 1)
            base.require(key not in settings, "Duplicate Go build setting.")
            settings[key] = value
    base.require(paths == [role_path(role)] and modules == ["localrmm"]
                 and settings.get("GOOS") == "darwin"
                 and settings.get("GOARCH") == arch and settings.get("CGO_ENABLED") == "0"
                 and not any(key.startswith("vcs.") for key in settings),
                 "Package binary metadata does not match its selected role and target.")
    return base.digest_file(path, base.MAX_BINARY)


def member_info(name: str, data: bytes, mode: int, mtime: int) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    info.mtime = mtime
    info.uid = info.gid = 0
    info.uname = info.gname = ""
    return info


def payload_manifest(version: str, commit: str, tree: str, go: str, arch: str,
                     files: dict[str, bytes]) -> dict:
    return {"schema": PAYLOAD_SCHEMA, "repository": base.REPOSITORY, "version": version,
            "sourceCommit": commit, "sourceTree": tree, "goVersion": "go" + go,
            "target": "darwin/" + arch, "candidateKind": "publisher-unsigned-service-test",
            "nativeAccepted": False, "publisherSigned": False, "notarized": False,
            "published": False, "productionReady": False,
            "assets": {name: {"size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                       for name, data in sorted(files.items())}}


def make_archive(path: Path, files: dict[str, bytes], manifest: dict, epoch: int) -> tuple[int, str]:
    manifest_bytes = base.canonical_json(manifest)
    base.require(len(manifest_bytes) <= MAX_MANIFEST, "Payload manifest is too large.")
    members = dict(files, **{"payload-manifest.json": manifest_bytes})
    with base.create_file(path) as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as archive:
                for name, data in sorted(members.items()):
                    mode = 0o755 if name.startswith("bin/") else 0o644
                    archive.addfile(member_info(name, data, mode, epoch), io.BytesIO(data))
    return base.digest_file(path, MAX_PACKAGE)


def verify_archive(path: Path, manifest: dict, epoch: int) -> None:
    target = manifest["target"]
    base.require(target in ("darwin/amd64", "darwin/arm64"), "Unknown package target.")
    arch = target.split("/")[1]
    expected = {"bin/" + role for role in ROLES} | {"source/source.tar", "TESTING.md", "payload-manifest.json"}
    seen: set[str] = set()
    total = 0
    with tarfile.open(path, "r:gz") as archive:
        for member in archive:
            base.require(member.name in expected and member.name not in seen and member.isfile()
                         and member.uid == 0 and member.gid == 0 and member.mtime == epoch
                         and member.mode == (0o755 if member.name.startswith("bin/") else 0o644),
                         "Package contains an unexpected, unsafe or duplicate member.")
            seen.add(member.name)
            limit = base.MAX_SOURCE if member.name == "source/source.tar" else (
                base.MAX_BINARY if member.name.startswith("bin/") else MAX_DOCUMENT)
            base.require(0 < member.size <= limit and total + member.size <= MAX_PACKAGE,
                         "Package member size exceeded its bound.")
            total += member.size
            data = archive.extractfile(member)
            base.require(data is not None, "Package member is unreadable.")
            with data:
                raw = data.read(limit + 1)
            base.require(len(raw) == member.size, "Package member was truncated.")
            if member.name == "payload-manifest.json":
                base.require(raw == base.canonical_json(manifest), "Payload manifest is not canonical.")
                continue
            entry = manifest["assets"].get(member.name)
            base.require(entry is not None and set(entry) == {"size", "sha256"}
                         and entry["size"] == len(raw) and entry["sha256"] == hashlib.sha256(raw).hexdigest(),
                         "Package member digest differs from the manifest.")
            if member.name.startswith("bin/"):
                head = raw[:16]
                base.require(head[:4] == base.MACHO_MAGIC
                             and int.from_bytes(head[4:8], "little") == base.MACHO_CPU[arch]
                             and int.from_bytes(head[12:16], "little") == 2,
                             "Package member is not a thin executable for its target.")
    base.require(seen == expected and set(manifest["assets"]) == expected - {"payload-manifest.json"},
                 "Package member set is incomplete or its manifest is not closed.")


def validate_output(manifest: dict, directory: Path, version: str, commit: str, tree: str,
                    pinned_go: str) -> None:
    base.require(set(manifest) == {"schema", "repository", "version", "sourceCommit", "sourceTree",
                                   "goVersion", "buildFlags", "candidateKind", "nativeAccepted",
                                   "publisherSigned", "notarized", "published", "productionReady", "assets"}
                 and manifest["schema"] == SCHEMA and manifest["repository"] == base.REPOSITORY
                 and manifest["version"] == version and manifest["sourceCommit"] == commit
                 and manifest["sourceTree"] == tree and manifest["goVersion"] == "go" + pinned_go
                 and manifest["buildFlags"] == list(base.BUILD_FLAGS)
                 and manifest["candidateKind"] == "publisher-unsigned-service-test"
                 and all(manifest[key] is False for key in
                         ("nativeAccepted", "publisherSigned", "notarized", "published", "productionReady")),
                 "Service package manifest identity or blocked status changed.")
    names = {f"tracebolt-{version}-darwin-{arch}-{role}"
             for arch in base.ARCHES for role in ("macos-package-prepare", "service-test-package.tar.gz")}
    base.require(set(manifest["assets"]) == names, "Service package asset set changed.")
    for arch in base.ARCHES:
        for role, limit in (("macos-package-prepare", base.MAX_BINARY),
                            ("service-test-package.tar.gz", MAX_PACKAGE)):
            name = f"tracebolt-{version}-darwin-{arch}-{role}"
            entry = manifest["assets"][name]
            base.require(set(entry) == {"role", "target", "size", "sha256"}
                         and entry["role"] == role.removesuffix(".tar.gz")
                         and entry["target"] == f"darwin/{arch}", "Service package asset role changed.")
            size, sha = base.digest_file(directory / name, limit)
            base.require(type(entry["size"]) is int and entry["size"] == size and entry["sha256"] == sha,
                         "Service package asset bytes changed.")
    raw = base.canonical_json(manifest)
    base.require((directory / "build-manifest.json").read_bytes() == raw
                 and set(path.name for path in directory.iterdir()) == names | {"build-manifest.json"},
                 "Service package output is not closed.")


def build_candidate(root: Path, version: str, commit: str, output: Path) -> dict:
    base.require(base.VERSION.fullmatch(version) is not None and len(version) <= 64,
                 "Invalid candidate version.")
    base.require(base.COMMIT.fullmatch(commit) is not None, "A full reviewed commit is required.")
    base.safe_path(root)
    base.safe_path(output, new_leaf=True)
    base.require(not output.is_relative_to(root) and not any(os.path.samefile(parent, root) for parent in output.parents),
                 "Output must be outside the exact source checkout.")
    pinned_go = base.go_version(root)
    tree = base.output_text(["git", "rev-parse", "HEAD^{tree}"], root).strip()
    base.require(base.COMMIT.fullmatch(tree) is not None, "A full source tree hash is required.")
    base.source_lease(root, commit, tree)
    base.reject_tracked_links(root)
    env = base.go_environment()
    base.require(base.output_text(["go", "env", "GOVERSION"], root, env=env).strip() == "go" + pinned_go,
                 "Use the exact pinned local Go toolchain.")
    base.source_lease(root, commit, tree)
    epoch_text = base.output_text(["git", "show", "-s", "--format=%ct", commit], root).strip()
    base.require(re.fullmatch(r"[0-9]{1,12}", epoch_text) is not None, "Invalid commit timestamp.")
    epoch = int(epoch_text)
    output.mkdir(mode=0o700)
    initial = output.stat()
    assets = {}
    with tempfile.TemporaryDirectory(prefix=".build-", dir=output) as scratch_name:
        scratch = Path(scratch_name)
        source = scratch / "source.tar"
        base.source_lease(root, commit, tree)
        with base.create_file(source) as stream:
            base.run(["git", "archive", "--format=tar", commit], root, stdout=stream,
                     timeout=180, limit_stdout=base.MAX_SOURCE)
        source_size, source_sha = base.digest_file(source, base.MAX_SOURCE)
        compile_root = scratch / "reviewed-source"
        base.extract_reviewed_archive(source, compile_root)
        base.require(base.go_version(compile_root) == pinned_go, "Reviewed archive Go version differs.")
        base.run(["go", "mod", "verify"], compile_root, env=env, timeout=180)
        required = list(PAYLOAD_STATIC.values()) + ["deploy/macos-release/prepare/main.go"]
        for name in required:
            base.require((compile_root / name).is_file(), "Reviewed source lacks package entry or runbook.")
        base.source_lease(root, commit, tree)
        for arch in base.ARCHES:
            target_env = dict(env, GOARCH=arch, GOAMD64="v1", GOARM64="v8.0")
            files = {"source/source.tar": source.read_bytes()}
            for dest, origin in PAYLOAD_STATIC.items():
                content = (compile_root / origin).read_bytes()
                base.require(0 < len(content) <= MAX_DOCUMENT, "Package runbook exceeded its bound.")
                files[dest] = content
            for role, package in ROLES.items():
                results = []
                for number in (1, 2):
                    base.source_lease(root, commit, tree)
                    built = scratch / f"{arch}-{role}-{number}"
                    base.run(["go", "build", *base.BUILD_FLAGS, "-o", str(built), package],
                             compile_root, env=target_env, timeout=600)
                    results.append(checked_binary(built, arch, role, compile_root, target_env,
                                                  pinned_go))
                    base.source_lease(root, commit, tree)
                base.require(results[0] == results[1], "Repeated builds did not produce identical bytes.")
                files["bin/" + role] = (scratch / f"{arch}-{role}-1").read_bytes()
                base.require(len(files["bin/" + role]) == results[0][0], "Binary changed before packaging.")
                if role == "macos-package-prepare":
                    helper_name = f"tracebolt-{version}-darwin-{arch}-{role}"
                    with base.create_file(output / helper_name) as stream:
                        stream.write(files["bin/" + role])
                    (output / helper_name).chmod(0o700)
                    base.require(checked_binary(output / helper_name, arch, role, compile_root,
                                                target_env, pinned_go) == results[0],
                                 "Standalone package helper changed.")
                    assets[helper_name] = {"role": role, "target": f"darwin/{arch}",
                                           "size": results[0][0], "sha256": results[0][1]}
            payload = payload_manifest(version, commit, tree, pinned_go, arch, files)
            pkg_name = f"tracebolt-{version}-darwin-{arch}-service-test-package.tar.gz"
            first = scratch / f"{arch}-package-1.tar.gz"
            second = scratch / f"{arch}-package-2.tar.gz"
            first_info = make_archive(first, files, payload, epoch)
            second_info = make_archive(second, files, payload, epoch)
            base.require(first_info == second_info and first.read_bytes() == second.read_bytes(),
                         "Repeated package assembly did not produce identical bytes.")
            verify_archive(first, payload, epoch)
            with first.open("rb") as stream, base.create_file(output / pkg_name) as target:
                shutil.copyfileobj(stream, target, 1 << 20)
            base.require(base.digest_file(output / pkg_name, MAX_PACKAGE) == first_info,
                         "Final package changed.")
            assets[pkg_name] = {"role": "service-test-package", "target": f"darwin/{arch}",
                                "size": first_info[0], "sha256": first_info[1]}
            base.source_lease(root, commit, tree)
        base.require(base.digest_file(source, base.MAX_SOURCE) == (source_size, source_sha),
                     "Reviewed source archive changed.")
    manifest = {"schema": SCHEMA, "repository": base.REPOSITORY, "version": version,
                "sourceCommit": commit, "sourceTree": tree, "goVersion": "go" + pinned_go,
                "buildFlags": list(base.BUILD_FLAGS), "candidateKind": "publisher-unsigned-service-test",
                "nativeAccepted": False, "publisherSigned": False, "notarized": False,
                "published": False, "productionReady": False, "assets": dict(sorted(assets.items()))}
    raw = base.canonical_json(manifest)
    base.require(len(raw) <= MAX_MANIFEST, "Build manifest exceeded its bound.")
    with base.create_file(output / "build-manifest.json") as stream:
        stream.write(raw)
    base.require(base.digest_file(output / "build-manifest.json", MAX_MANIFEST) ==
                 (len(raw), hashlib.sha256(raw).hexdigest()) and
                 set(item.name for item in output.iterdir()) == set(assets) | {"build-manifest.json"} and
                 (output.stat().st_dev, output.stat().st_ino, output.stat().st_uid, output.stat().st_mode & 0o777) ==
                 (initial.st_dev, initial.st_ino, initial.st_uid, 0o700), "Candidate output was altered.")
    validate_output(manifest, output, version, commit, tree, pinned_go)
    base.source_lease(root, commit, tree)
    return manifest


def main() -> None:
    parser = __import__("argparse").ArgumentParser(allow_abbrev=False)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build_candidate(ROOT, args.version, args.source_commit, args.output)
    print("Unsigned service test packages prepared; nothing was installed, signed, notarized or published.")


if __name__ == "__main__":
    try:
        main()
    except (base.Rejected, OSError, UnicodeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error) if isinstance(error, base.Rejected) else
                         "Candidate preparation failed; preserve partial output for inspection.") from None
