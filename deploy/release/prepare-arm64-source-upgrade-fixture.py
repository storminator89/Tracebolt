#!/usr/bin/env python3
"""Build two exact ARM64 source generations for the approved disposable gate.

This prepares local fixtures only. It never executes a built Tracebolt program,
installs a service, publishes a release, or claims signed-release provenance.
Distinct vcs.revision metadata binds each ELF to its clean checkout; it does not
imply a behavioral difference when only acceptance-harness source has changed.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import stat
import struct
import subprocess
import sys

PRIOR_SOURCE = "7b20a93e481feb1f7433ee0ef6c912a35f68ce6d"
ROLES = ("agent-service", "enroll-agent", "lan-agent", "socket-owner-reader")
SCHEMA = "tracebolt.arm64-source-upgrade-fixture.v1"
MAX_BINARY = 128 << 20
MAX_SOURCE = 256 << 20
COMMIT = re.compile(r"[0-9a-f]{40}")


class Rejected(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Rejected(reason)


def require_gate(env, system, machine, maxsize, uid, euid):
    # Keep this pure and first: no filesystem, subprocess, build or host effects.
    expected = {
        "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": "Linux", "RUNNER_ARCH": "ARM64",
        "TRACEBOLT_APPROVED_SYSTEMD_TEST": "1",
        "TRACEBOLT_APPROVED_READ_ADMIN_V2_SYSTEMD_TEST": "1",
        "TRACEBOLT_READ_ADMIN_PROFILE": "tracebolt.linux-read-admin.v2",
        "TRACEBOLT_APPROVED_READ_ADMIN_PTRACE": "true",
        "TRACEBOLT_APPROVED_READ_ADMIN_UPGRADE": "true",
    }
    source = env.get("GITHUB_SHA")
    require(all(env.get(key) == value for key, value in expected.items()) and
            system == "linux" and machine == "aarch64" and maxsize > 2**32 and
            type(uid) is int and type(euid) is int and uid > 0 and euid == uid and
            env.get("TRACEBOLT_READ_ADMIN_TRANSPORT") in ("tls", "http-test") and
            env.get("TRACEBOLT_READ_ADMIN_SCENARIO") in ("complete", "cancel-enrollment", "retained-journal") and
            type(source) is str and COMMIT.fullmatch(source) is not None and
            env.get("TRACEBOLT_READ_ADMIN_REVIEWED_SOURCE") == source and source != PRIOR_SOURCE,
            "Explicit native ARM64 source-upgrade fixture approval is required; no work started.")
    return source


def build_environment(env):
    # Do not inherit credentials, Git overrides, compiler/linker flags, or proxy
    # authentication. Dependency/cache locations are ordinary runner locations.
    result = {key: env[key] for key in ("PATH", "HOME", "TMPDIR", "GOCACHE", "GOMODCACHE") if key in env}
    result.update(LANG="C", LC_ALL="C", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL="/dev/null",
                  GIT_TERMINAL_PROMPT="0", GOENV="off", GOTOOLCHAIN="local", GOWORK="off",
                  GOFLAGS="", GOEXPERIMENT="", CGO_ENABLED="0", GOOS="linux", GOARCH="arm64", GOARM64="v8.0")
    return result


def run(argv, root, env, *, stdout=subprocess.PIPE):
    # Output can contain paths or dependency errors; callers expose only fixed
    # failures. Never run any of the newly built artifacts.
    return subprocess.run(argv, cwd=root, env=env, check=True, stdin=subprocess.DEVNULL,
                          stdout=stdout, stderr=subprocess.PIPE, timeout=300)


def text_command(argv, root, env):
    output = run(argv, root, env).stdout
    require(type(output) is bytes and len(output) <= 1 << 20, "Bounded build command output required.")
    return output.decode("utf-8", errors="strict").strip()


def exact_path(value):
    path = Path(value)
    require(path.is_absolute() and str(path) == value and path == path.resolve(),
            "Exact absolute non-symlink fixture paths are required.")
    return path


def verify_checkout(root, revision, env):
    require(text_command(["git", "rev-parse", "--show-toplevel"], root, env) == str(root),
            "A repository-root checkout is required.")
    require(text_command(["git", "rev-parse", "--verify", "HEAD^{commit}"], root, env) == revision,
            "Source checkout revision mismatch.")
    require(not text_command(["git", "status", "--porcelain=v1", "--untracked-files=all"], root, env),
            "Source checkouts must remain clean, including untracked files.")


def verify_toolchain(root, env):
    raw = (root / "go.mod").read_text(encoding="utf-8")
    versions = re.findall(r"^go ([0-9]+\.[0-9]+\.[0-9]+)$", raw, re.M)
    require(len(versions) == 1, "The exact source Go toolchain is required.")
    expected = "go" + versions[0]
    facts = json.loads(text_command(["go", "env", "-json", "GOHOSTOS", "GOHOSTARCH", "GOVERSION"], root, env))
    require(facts == {"GOHOSTOS": "linux", "GOHOSTARCH": "arm64", "GOVERSION": expected},
            "The exact native ARM64 Go toolchain is required.")
    return expected


def verify_build_info(raw, role, revision, version):
    require(type(raw) is str and 0 < len(raw.encode("utf-8")) <= 1 << 20,
            "Bounded Go build metadata required.")
    lines = raw.splitlines()
    require(lines and lines[0].endswith(": " + version), "Built Go toolchain mismatch.")
    path, module, settings = None, None, {}
    for line in lines[1:]:
        fields = line.split("\t")
        require(len(fields) >= 3 and fields[0] == "", "Malformed Go build metadata.")
        if fields[1] == "path":
            require(path is None and len(fields) == 3, "Duplicate Go role metadata.")
            path = fields[2]
        elif fields[1] == "mod":
            require(module is None and len(fields) >= 3, "Duplicate Go module metadata.")
            module = fields[2]
        elif fields[1] == "build":
            require(len(fields) == 3 and "=" in fields[2], "Malformed Go build setting.")
            key, value = fields[2].split("=", 1)
            require(key not in settings, "Duplicate Go build setting.")
            settings[key] = value
    expected = {"GOOS": "linux", "GOARCH": "arm64", "GOARM64": "v8.0", "CGO_ENABLED": "0",
                "-trimpath": "true", "vcs": "git", "vcs.revision": revision, "vcs.modified": "false"}
    require(role in ROLES and path == "localrmm/cmd/" + role and module == "localrmm" and
            all(settings.get(key) == value for key, value in expected.items()),
            "Built artifact role, native architecture, or exact clean source binding mismatch.")


def file_evidence(path, limit, *, executable=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == os.geteuid() and
                stat.S_IMODE(before.st_mode) == 0o600 and 0 < before.st_size <= limit,
                "Private fixture file contract mismatch.")
        if executable:
            header = stream.read(64)
            require(len(header) == 64 and header[:7] == b"\x7fELF\x02\x01\x01" and
                    struct.unpack_from("<H", header, 16)[0] in (2, 3) and
                    struct.unpack_from("<H", header, 18)[0] == 183 and
                    struct.unpack_from("<I", header, 20)[0] == 1,
                    "A native ELF64 little-endian AArch64 artifact is required.")
            stream.seek(0)
        checksum = hashlib.file_digest(stream, "sha256").hexdigest()
        after, current = os.fstat(stream.fileno()), path.lstat()
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, key) == getattr(after, key) == getattr(current, key) for key in fields),
                "Fixture bytes changed during validation.")
        return {"size": before.st_size, "sha256": checksum}


def build_generation(root, output, revision, env):
    verify_checkout(root, revision, env)
    version = verify_toolchain(root, env)
    run(["go", "mod", "verify"], root, env)
    output.mkdir(mode=0o700)
    files = {}
    for role in ROLES:
        path = output / role
        run(["go", "build", "-buildvcs=true", "-trimpath", "-mod=readonly", "-o", str(path), "./cmd/" + role], root, env)
        os.chmod(path, 0o600)
        before = file_evidence(path, MAX_BINARY, executable=True)
        metadata = text_command(["go", "version", "-m", str(path)], root, env)
        verify_build_info(metadata, role, revision, version)
        require(before == file_evidence(path, MAX_BINARY, executable=True), "Artifact changed while checking source metadata.")
        files[role] = before
    archive = output / "source.tar"
    fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        run(["git", "archive", "--format=tar", revision], root, env, stdout=stream)
        stream.flush()
        os.fsync(stream.fileno())
    files["source"] = file_evidence(archive, MAX_SOURCE)
    verify_checkout(root, revision, env)
    return {"sourceCommit": revision, "files": files}


def main(argv=None):
    candidate = require_gate(os.environ, sys.platform, platform.machine(), sys.maxsize, os.getuid(), os.geteuid())
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--prior-checkout", required=True)
    parser.add_argument("--candidate-checkout", required=True)
    parser.add_argument("--directory", required=True)
    args = parser.parse_args(argv)
    prior_root, candidate_root, output = map(exact_path, (args.prior_checkout, args.candidate_checkout, args.directory))
    require(prior_root != candidate_root and not prior_root.is_relative_to(candidate_root) and
            not candidate_root.is_relative_to(prior_root) and
            not output.is_relative_to(prior_root) and not output.is_relative_to(candidate_root) and
            not prior_root.is_relative_to(output) and not candidate_root.is_relative_to(output) and not output.exists(),
            "Separate clean checkouts and a new output directory outside both are required.")
    env = build_environment(os.environ)
    verify_checkout(prior_root, PRIOR_SOURCE, env)
    verify_checkout(candidate_root, candidate, env)
    output.mkdir(mode=0o700)
    proof = {"schemaVersion": SCHEMA, "architecture": "arm64", "baselineKind": "source-built",
             "priorSourceCommit": PRIOR_SOURCE, "candidateSourceCommit": candidate}
    proof["prior"] = build_generation(prior_root, output / "prior", PRIOR_SOURCE, env)
    proof["candidate"] = build_generation(candidate_root, output / "candidate", candidate, env)
    require(proof["prior"]["files"]["lan-agent"]["sha256"] != proof["candidate"]["files"]["lan-agent"]["sha256"],
            "Distinct exact-source ARM64 executable bytes are required.")
    # A moved/dirty prior checkout after the candidate build must also fail.
    verify_checkout(prior_root, PRIOR_SOURCE, env)
    verify_checkout(candidate_root, candidate, env)
    raw = (json.dumps(proof, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    require(len(raw) <= 4096, "Bounded fixture proof required.")
    fd = os.open(output / "proof.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print("Prepared two exact native ARM64 source-build fixtures. No installer or built artifact was executed.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (Rejected, OSError, ValueError, subprocess.SubprocessError):
        raise SystemExit("ARM64 source-upgrade fixture preparation failed; no installation was performed.") from None
