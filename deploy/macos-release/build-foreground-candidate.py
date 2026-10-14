#!/usr/bin/env python3
"""Prepare publisher-unsigned, non-installable macOS foreground review bytes only.

This never runs a target binary, signs, installs, dispatches or publishes one.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tarfile
import tempfile
import time


ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = "storminator89/Tracebolt"
SCHEMA = "tracebolt.macos-foreground-candidate.v1"
ROLES = ("enroll-agent", "macos-agent")
ARCHES = ("amd64", "arm64")
BUILD_FLAGS = ("-buildvcs=false", "-trimpath", "-mod=readonly")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
VERSION = re.compile(r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?\Z")
MAX_BINARY = 64 << 20
MAX_SOURCE = 128 << 20
MAX_MANIFEST = 16 << 10
MAX_CAPTURE = 2 << 20
MAX_STDERR = 64 << 10
MAX_EXTRACTED = 256 << 20
MAX_ARCHIVE_MEMBERS = 30000
MACHO_MAGIC = b"\xcf\xfa\xed\xfe"  # Thin, little-endian, 64-bit Mach-O.
MACHO_CPU = {"amd64": 0x01000007, "arm64": 0x0100000C}


class Rejected(Exception):
    pass


def require(condition: bool, message: str) -> None:
    if not condition:
        raise Rejected(message)


def run(argv: list[str], root: Path, *, env: dict | None = None, stdout=None,
        timeout: int = 300, limit_stdout: int = MAX_CAPTURE):
    """Bound both pipes while the trusted Git/Go child runs; reap on failure."""
    child = subprocess.Popen(argv, cwd=root, env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
    captured = bytearray()
    stderr = bytearray()
    selector = selectors.DefaultSelector()
    deadline = time.monotonic() + timeout
    try:
        for stream, label in ((child.stdout, "stdout"), (child.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        written = 0
        while selector.get_map():
            remaining = deadline - time.monotonic()
            require(remaining > 0, "A bounded source/tool command timed out.")
            for key, _ in selector.select(min(remaining, 0.5)):
                chunk = os.read(key.fileobj.fileno(), 1 << 16)
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                if key.data == "stderr":
                    stderr.extend(chunk)
                    require(len(stderr) <= MAX_STDERR, "Source/tool stderr exceeded its bound.")
                elif stdout is None:
                    captured.extend(chunk)
                    require(len(captured) <= limit_stdout, "Source/tool stdout exceeded its bound.")
                else:
                    written += len(chunk)
                    require(written <= limit_stdout, "Source archive exceeded its bound.")
                    stdout.write(chunk)
        require(child.wait(timeout=max(0.1, deadline - time.monotonic())) == 0,
                "A source/tool command failed; preserve partial output for inspection.")
        return subprocess.CompletedProcess(argv, 0, None if stdout is not None else bytes(captured), bytes(stderr))
    except Exception:
        if child.poll() is None:
            os.killpg(child.pid, signal.SIGKILL)
        child.wait()
        raise
    finally:
        selector.close()
        child.stdout.close()
        child.stderr.close()


def output_text(argv: list[str], root: Path, *, env: dict | None = None) -> str:
    raw = run(argv, root, env=env, timeout=30).stdout
    require(raw is not None and len(raw) <= 2 << 20, "Source/tool output exceeded its bound.")
    return raw.decode("utf-8", "strict")


def safe_path(path: Path, *, new_leaf: bool = False) -> None:
    require(path.is_absolute() and path == Path(os.path.normpath(path)), "Use a canonical absolute path.")
    current = Path("/")
    for part in path.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            require(new_leaf and current == path, "Missing output parent.")
            return
        require(not stat.S_ISLNK(info.st_mode), "Symlink paths are not accepted.")
        if current != path or not new_leaf:
            require(stat.S_ISDIR(info.st_mode), "Path parent is not a directory.")
        else:
            raise Rejected("Output already exists; never replace or reuse it.")
    require(not new_leaf, "Output already exists; never replace or reuse it.")


def go_version(root: Path) -> str:
    lines = [line.split()[1] for line in (root / "go.mod").read_text().splitlines()
             if line.startswith("go ") and len(line.split()) == 2]
    require(len(lines) == 1 and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", lines[0]), "Invalid pinned Go version.")
    return lines[0]


def go_environment() -> dict[str, str]:
    env = dict(os.environ)
    env.update({"GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off", "GOFLAGS": "-mod=readonly",
                "CGO_ENABLED": "0", "GOOS": "darwin", "GOEXPERIMENT": "", "GOPROXY": "off",
                "GOSUMDB": "off", "GOVCS": "*:off"})
    return env


def source_lease(root: Path, commit: str, tree: str) -> None:
    top = output_text(["git", "rev-parse", "--show-toplevel"], root).strip()
    require(top == str(root), "The selected source is not the exact repository root.")
    require(output_text(["git", "rev-parse", "HEAD"], root).strip() == commit,
            "Source commit changed during candidate preparation.")
    require(output_text(["git", "rev-parse", "HEAD^{tree}"], root).strip() == tree,
            "Source tree changed during candidate preparation.")
    require(not output_text(["git", "status", "--porcelain=v1", "--untracked-files=all"], root),
            "A dirty index, tracked file or untracked file blocks exact-source preparation.")


def reject_tracked_links(root: Path) -> None:
    raw = run(["git", "ls-files", "--stage", "-z"], root, timeout=30).stdout
    require(raw is not None and len(raw) <= 2 << 20, "Tracked source listing exceeded its bound.")
    for record in raw.split(b"\0"):
        if not record:
            continue
        mode = record.split(b" ", 1)[0]
        require(mode in (b"100644", b"100755"), "Linked, submodule or unusual tracked source is unsupported.")
    flags = run(["git", "ls-files", "-v", "-z"], root, timeout=30).stdout
    require(flags is not None and len(flags) <= 2 << 20, "Tracked index flags exceeded their bound.")
    for record in flags.split(b"\0"):
        if record:
            require(record.startswith(b"H "), "Assume-unchanged, skip-worktree or other unusual index flags are unsupported.")


def extract_reviewed_archive(archive: Path, destination: Path) -> None:
    """Unpack only bounded ordinary Git source members, without tarfile.extract."""
    destination.mkdir(mode=0o700)
    seen: set[str] = set()
    count = 0
    total = 0
    with tarfile.open(archive, mode="r:") as source:
        for member in source:
            count += 1
            require(count <= MAX_ARCHIVE_MEMBERS, "Source archive has too many members.")
            name = member.name.removesuffix("/") if member.isdir() else member.name
            parts = name.split("/")
            require(name and not name.startswith("/") and all(part not in ("", ".", "..") for part in parts)
                    and "\\" not in name and "\x00" not in name and name not in seen,
                    "Source archive path is unsafe or duplicated.")
            seen.add(name)
            require(member.isdir() or member.isfile(), "Source archive contains a link or special member.")
            target = destination.joinpath(*parts)
            if member.isdir():
                target.mkdir(mode=0o700, parents=True, exist_ok=True)
                require(target.is_dir() and not target.is_symlink(), "Source archive directory collision.")
                continue
            require(0 <= member.size <= MAX_SOURCE and total + member.size <= MAX_EXTRACTED,
                    "Source archive member or extracted bytes exceeded their bound.")
            total += member.size
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            with create_file(target) as output:
                input_stream = source.extractfile(member)
                require(input_stream is not None, "Source archive member cannot be read.")
                remaining = member.size
                with input_stream:
                    while remaining:
                        chunk = input_stream.read(min(remaining, 1 << 20))
                        require(bool(chunk), "Source archive member was truncated.")
                        output.write(chunk)
                        remaining -= len(chunk)
    require((destination / "go.mod").is_file() and (destination / "go.sum").is_file(),
            "The reviewed source archive lacks required module inputs.")


def digest_file(path: Path, limit: int) -> tuple[int, str]:
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
            and not info.st_mode & 0o022 and 0 < info.st_size <= limit,
            "An output is linked, unprotected or outside its size bound.")
    digest = hashlib.sha256()
    total = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            total += len(chunk)
            require(total <= limit, "An output exceeded its size bound while hashing.")
            digest.update(chunk)
    after = path.lstat()
    require(total == info.st_size and (after.st_dev, after.st_ino, after.st_mode, after.st_uid,
                                       after.st_nlink, after.st_size, after.st_mtime_ns, after.st_ctime_ns) ==
            (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
             info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns),
            "An output changed while being hashed.")
    return total, digest.hexdigest()


def binary_info(path: Path, arch: str, role: str, root: Path, env: dict) -> tuple[int, str]:
    with path.open("rb") as stream:
        header = stream.read(16)
    require(len(header) == 16 and header[:4] == MACHO_MAGIC
            and int.from_bytes(header[4:8], "little") == MACHO_CPU[arch]
            and int.from_bytes(header[12:16], "little") == 2,
            "A built binary is not a thin Mach-O executable for the selected architecture.")
    lines = output_text(["go", "version", "-m", str(path)], root, env=env).splitlines()
    actual_path = None
    settings: dict[str, str] = {}
    for line in lines:
        fields = line.strip().split("\t")
        if len(fields) >= 2 and fields[0] == "path":
            require(actual_path is None, "Duplicate binary role metadata.")
            actual_path = fields[1]
        if len(fields) >= 2 and fields[0] == "build" and "=" in fields[1]:
            key, value = fields[1].split("=", 1)
            require(key not in settings, "Duplicate binary build metadata.")
            settings[key] = value
    require(actual_path == f"localrmm/cmd/{role}" and settings.get("GOOS") == "darwin"
            and settings.get("GOARCH") == arch and settings.get("CGO_ENABLED") == "0"
            and not any(key.startswith("vcs.") for key in settings),
            "Binary build metadata does not bind the reviewed role and target or unexpectedly claims VCS identity.")
    return digest_file(path, MAX_BINARY)


def asset_names(version: str) -> tuple[str, ...]:
    return tuple(f"tracebolt-{version}-darwin-{arch}-{role}" for arch in ARCHES for role in ROLES)


def canonical_json(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def create_file(path: Path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb")


def validate_manifest(manifest: dict, directory: Path, version: str, commit: str, tree: str, pinned_go: str) -> None:
    require(set(manifest) == {"schema", "repository", "version", "sourceCommit", "sourceTree", "goVersion",
                              "buildFlags", "candidateKind", "nativeAccepted", "installable", "publisherSigned",
                              "published", "assets"}, "Manifest fields are not closed.")
    require(manifest["schema"] == SCHEMA and manifest["repository"] == REPOSITORY
            and manifest["version"] == version and manifest["sourceCommit"] == commit
            and manifest["sourceTree"] == tree and manifest["goVersion"] == "go" + pinned_go
            and manifest["buildFlags"] == list(BUILD_FLAGS)
            and manifest["candidateKind"] == "publisher-unsigned-foreground-source-review"
            and all(manifest[key] is False for key in ("nativeAccepted", "installable", "publisherSigned", "published")),
            "Manifest identity or blocked status changed.")
    source_name = f"tracebolt-{version}-source.tar"
    require(set(manifest["assets"]) == set(asset_names(version)) | {source_name}, "Manifest asset set changed.")
    for name, entry in manifest["assets"].items():
        require(set(entry) == {"role", "target", "size", "sha256"}, "Manifest asset fields are not closed.")
        if name == source_name:
            require(entry["role"] == "source" and entry["target"] == "none", "Source archive role changed.")
            limit = MAX_SOURCE
        else:
            matches = [(arch, role) for arch in ARCHES for role in ROLES
                       if name == f"tracebolt-{version}-darwin-{arch}-{role}"]
            require(len(matches) == 1 and entry["target"] == f"darwin/{matches[0][0]}"
                    and entry["role"] == matches[0][1], "Binary role or target changed.")
            limit = MAX_BINARY
        size, sha = digest_file(directory / name, limit)
        require(type(entry["size"]) is int and entry["size"] == size and entry["sha256"] == sha,
                "Asset hash or size changed.")
    require(set(item.name for item in directory.iterdir()) == set(manifest["assets"]) | {"build-manifest.json"},
            "Unexpected candidate output file.")


def build_candidate(root: Path, version: str, commit: str, output: Path) -> dict:
    require(VERSION.fullmatch(version) is not None and len(version) <= 64, "Invalid candidate version.")
    require(COMMIT.fullmatch(commit) is not None, "A full lowercase reviewed source commit is required.")
    safe_path(root)
    safe_path(output, new_leaf=True)
    require(not output.is_relative_to(root), "Candidate output must be outside the source checkout.")
    require(not any(os.path.samefile(parent, root) for parent in output.parents),
            "Candidate output parent aliases the source checkout.")
    pinned_go = go_version(root)
    tree = output_text(["git", "rev-parse", "HEAD^{tree}"], root).strip()
    require(COMMIT.fullmatch(tree) is not None, "A full source tree hash is required.")
    source_lease(root, commit, tree)
    reject_tracked_links(root)
    env = go_environment()
    require(output_text(["go", "env", "GOVERSION"], root, env=env).strip() == "go" + pinned_go,
            "Use the exact pinned local Go toolchain.")
    source_lease(root, commit, tree)
    output.mkdir(mode=0o700)
    initial = output.stat()
    assets = {}
    try:
        with tempfile.TemporaryDirectory(prefix=".build-", dir=output) as scratch_name:
            scratch = Path(scratch_name)
            source_name = f"tracebolt-{version}-source.tar"
            archive = scratch / source_name
            source_lease(root, commit, tree)
            with create_file(archive) as stream:
                run(["git", "archive", "--format=tar", commit], root, stdout=stream,
                    timeout=180, limit_stdout=MAX_SOURCE)
            source_size, source_sha = digest_file(archive, MAX_SOURCE)
            source_lease(root, commit, tree)
            compile_root = scratch / "reviewed-source"
            extract_reviewed_archive(archive, compile_root)
            require(go_version(compile_root) == pinned_go, "Archive Go version differs from the reviewed checkout.")
            run(["go", "mod", "verify"], compile_root, env=env, timeout=180)
            source_lease(root, commit, tree)
            for arch in ARCHES:
                target_env = dict(env, GOARCH=arch, GOAMD64="v1", GOARM64="v8.0")
                for role in ROLES:
                    results = []
                    for number in (1, 2):
                        source_lease(root, commit, tree)
                        path = scratch / f"{arch}-{role}-{number}"
                        run(["go", "build", *BUILD_FLAGS, "-o", str(path), f"./cmd/{role}"], compile_root,
                            env=target_env, timeout=600)
                        results.append(binary_info(path, arch, role, compile_root, target_env))
                        source_lease(root, commit, tree)
                    require(results[0] == results[1], "Repeated builds did not produce identical bytes.")
                    name = f"tracebolt-{version}-darwin-{arch}-{role}"
                    with (scratch / f"{arch}-{role}-1").open("rb") as source, create_file(output / name) as target:
                        shutil.copyfileobj(source, target, 1 << 20)
                    require(binary_info(output / name, arch, role, compile_root, target_env) == results[0],
                            "Final binary copy differs from the verified build.")
                    assets[name] = {"role": role, "target": f"darwin/{arch}", "size": results[0][0],
                                    "sha256": results[0][1]}
            with archive.open("rb") as source, create_file(output / source_name) as target:
                shutil.copyfileobj(source, target, 1 << 20)
            require(digest_file(output / source_name, MAX_SOURCE) == (source_size, source_sha),
                    "Final source archive copy differs from the reviewed snapshot.")
            assets[source_name] = {"role": "source", "target": "none", "size": source_size,
                                   "sha256": source_sha}
        source_lease(root, commit, tree)
        manifest = {"schema": SCHEMA, "repository": REPOSITORY, "version": version,
                    "sourceCommit": commit, "sourceTree": tree, "goVersion": "go" + pinned_go,
                    "buildFlags": list(BUILD_FLAGS), "candidateKind": "publisher-unsigned-foreground-source-review",
                    "nativeAccepted": False, "installable": False, "publisherSigned": False,
                    "published": False, "assets": dict(sorted(assets.items()))}
        raw = canonical_json(manifest)
        require(len(raw) <= MAX_MANIFEST, "Manifest exceeded its size bound.")
        with create_file(output / "build-manifest.json") as stream:
            stream.write(raw)
        require(digest_file(output / "build-manifest.json", MAX_MANIFEST) ==
                (len(raw), hashlib.sha256(raw).hexdigest()) and
                (output / "build-manifest.json").read_bytes() == raw,
                "Final manifest bytes changed.")
        validate_manifest(manifest, output, version, commit, tree, pinned_go)
        require((output.stat().st_dev, output.stat().st_ino, output.stat().st_uid) ==
                (initial.st_dev, initial.st_ino, initial.st_uid) and output.stat().st_mode & 0o777 == 0o700,
                "Candidate output directory changed.")
        source_lease(root, commit, tree)
        return manifest
    except Exception:
        # Preserve partial output for inspection. Never adopt or overwrite it.
        raise


def main() -> None:
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build_candidate(ROOT, args.version, args.source_commit, args.output)
    print("Publisher-unsigned foreground source-review candidate prepared. No native execution, installation, publisher signing or publication occurred.")


if __name__ == "__main__":
    try:
        main()
    except (Rejected, OSError, UnicodeError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise SystemExit(str(error) if isinstance(error, Rejected) else
                         "Candidate preparation failed; preserve the partial output for inspection. Nothing was published.") from None
