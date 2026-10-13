#!/usr/bin/env python3
"""Capture fixed help/manual sources only; --check invokes no command or native API."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import signal
import stat
import subprocess
import sys
import time
import unicodedata
import zlib
from types import MappingProxyType

ROOT = Path(__file__).resolve().parents[2]
DESTINATION = ROOT / "artifacts/review/macos-tool-docs.json"
# No caller-supplied executable, arguments, domain, service, PID, predicate or path.
COMMANDS = MappingProxyType({
    "product-version": ("/usr/bin/sw_vers", "-productVersion"),
    "build-version": ("/usr/bin/sw_vers", "-buildVersion"),
    "kernel-release": ("/usr/bin/uname", "-r"),
    "architecture": ("/usr/bin/uname", "-m"),
    "launchctl-help": ("/bin/launchctl", "help"),
    "launchctl-help-print": ("/bin/launchctl", "help", "print"),
    "launchctl-help-list": ("/bin/launchctl", "help", "list"),
    "launchctl-help-print-disabled": ("/bin/launchctl", "help", "print-disabled"),
    "log-help": ("/usr/bin/log", "help"),
    "log-help-show": ("/usr/bin/log", "help", "show"),
})
VERSION_IDS = tuple(COMMANDS)[:4]
RUNNERS = MappingProxyType({"macos-15": ("ARM64", "arm64"),
                            "macos-15-intel": ("X64", "x86_64")})
LIMIT_BYTES = 64 * 1024  # Shared stdout/stderr budget per help command.
STDERR_LIMIT_BYTES = 16 * 1024  # Drained and discarded, never artifact text.
TIMEOUT_SECONDS = 5
BINARY_LIMIT_BYTES = 32 * 1024 * 1024
SOURCE_PATHS = (".github/workflows/macos-tool-docs.yml", "tests/macostooldocs/run.py",
                "tests/macostooldocs/test_run.py", "docs/macos-tool-docs.md")
CHILD_ENV = MappingProxyType({"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
MANUAL_SOURCES = MappingProxyType({
    "launchctl-man": ("launchctl", "/usr/share/man/man1/launchctl.1", "none"),
    "launchctl-man-gzip": ("launchctl", "/usr/share/man/man1/launchctl.1.gz", "gzip"),
    "log-man": ("log", "/usr/share/man/man1/log.1", "none"),
    "log-man-gzip": ("log", "/usr/share/man/man1/log.1.gz", "gzip"),
})
MANUAL_SOURCE_LIMIT = 128 * 1024
MANUAL_TEXT_LIMIT = 256 * 1024


def check_commands():
    # This is a safety assertion, not an extensible policy or shell filter.
    if tuple(COMMANDS.values()) != (
        ("/usr/bin/sw_vers", "-productVersion"),
        ("/usr/bin/sw_vers", "-buildVersion"),
        ("/usr/bin/uname", "-r"), ("/usr/bin/uname", "-m"),
        ("/bin/launchctl", "help"), ("/bin/launchctl", "help", "print"),
        ("/bin/launchctl", "help", "list"),
        ("/bin/launchctl", "help", "print-disabled"),
        ("/usr/bin/log", "help"), ("/usr/bin/log", "help", "show"),
    ):
        raise ValueError("documentation command allowlist changed; fresh review required")
    if tuple(MANUAL_SOURCES.values()) != (
        ("launchctl", "/usr/share/man/man1/launchctl.1", "none"),
        ("launchctl", "/usr/share/man/man1/launchctl.1.gz", "gzip"),
        ("log", "/usr/share/man/man1/log.1", "none"),
        ("log", "/usr/share/man/man1/log.1.gz", "gzip"),
    ):
        raise ValueError("manual source allowlist changed; fresh review required")


def hosted_context(env, system):
    label = env.get("TRACEBOLT_RUNNER_LABEL")
    if system != "darwin" or label not in RUNNERS:
        raise ValueError("standard hosted macOS 15 runner required")
    runner_arch, machine = RUNNERS[label]
    expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
                "TRACEBOLT_RUNNER_OS": "macOS", "TRACEBOLT_RUNNER_ARCH": runner_arch,
                "TRACEBOLT_REPOSITORY_PRIVATE": "false"}
    if any(env.get(key) != value for key, value in expected.items()):
        raise ValueError("unexpected public hosted runner context")
    sha = env.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("invalid workflow source identity")
    # Never retain arbitrary environment values, machine names, account names or IDs.
    result = {"runnerLabel": label, "runnerOS": "macOS", "runnerArch": runner_arch,
              "expectedMachine": machine, "workflowSHA": sha}
    for key in ("ImageOS", "ImageVersion"):
        value = env.get(key, "")
        result[key] = value if re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", value) else None
    return result


def capture(command_id):
    """Dispatch only an exact allowlisted tuple; discard failed/incomplete output."""
    argv = COMMANDS[command_id]  # Unknown IDs fail before process creation.
    limit = 128 if command_id in VERSION_IDS else LIMIT_BYTES
    stderr_limit = min(limit, STDERR_LIMIT_BYTES)
    started = time.monotonic()
    record = {"id": command_id, "argv": list(argv), "timeoutSeconds": TIMEOUT_SECONDS,
              "byteLimit": limit, "status": "inconclusive", "exitCode": None,
              "reason": "spawn_failed", "capturedBytes": 0, "text": None,
              "stderrByteLimit": stderr_limit, "stderrDiscarded": True}
    try:
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                   shell=False, cwd="/", env=dict(CHILD_ENV),
                                   start_new_session=True, close_fds=True)
    except OSError:
        return record  # Exception text can expose local paths; never retain it.
    data = bytearray()
    counts = {"stdout": 0, "stderr": 0}
    reason = None
    try:
        with selectors.DefaultSelector() as selector:
            for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, data=name)
            while selector.get_map():
                remaining = TIMEOUT_SECONDS - (time.monotonic() - started)
                if remaining <= 0:
                    reason = "timeout"
                    break
                for key, _ in selector.select(remaining):
                    stream_limit = stderr_limit if key.data == "stderr" else limit
                    read_limit = min(4096, limit + 1 - sum(counts.values()),
                                     stream_limit + 1 - counts[key.data])
                    chunk = os.read(key.fileobj.fileno(), read_limit)
                    if not chunk:
                        selector.unregister(key.fileobj)
                    else:
                        counts[key.data] += len(chunk)
                        if key.data == "stdout":
                            data.extend(chunk)
                        # Stderr is deliberately never buffered or decoded.
                        if counts["stderr"] > stderr_limit:
                            reason = "stderr_limit"
                            break
                        if sum(counts.values()) > limit:
                            reason = "output_limit"
                            break
                if reason:
                    break
            if not reason:
                try:
                    process.wait(timeout=max(0.001, TIMEOUT_SECONDS - (time.monotonic() - started)))
                except subprocess.TimeoutExpired:
                    reason = "timeout"
    except (OSError, ValueError):
        reason = "capture_failed"
    finally:
        # Only this freshly spawned command's session; never a discovered host PID.
        if reason:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            reason = "cleanup_timeout"
        process.stdout.close()
        process.stderr.close()
    record["exitCode"] = process.returncode
    record["capturedBytes"] = min(sum(counts.values()), limit)
    record["stdoutBytes"] = min(counts["stdout"], limit)
    record["stderrBytes"] = min(counts["stderr"], stderr_limit)
    record["elapsedMilliseconds"] = round((time.monotonic() - started) * 1000)
    if reason or process.returncode != 0:
        record["reason"] = reason or "nonzero_exit"
        return record
    if counts["stderr"]:
        record["reason"] = "stderr_present"
        return record  # Unknown warnings invalidate even otherwise plausible stdout.
    try:
        text = bytes(data).decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        record["reason"] = "invalid_text"
        return record
    if not text.strip() or any(ord(c) < 32 and c not in "\t\r\n" or ord(c) == 127 for c in text):
        record["reason"] = "invalid_text"
        return record
    if command_id in VERSION_IDS:
        patterns = {"product-version": r"15(?:\.[0-9]+){1,2}",
                    "build-version": r"[0-9]{1,3}[A-Z][0-9]{1,6}[a-z]?",
                    "kernel-release": r"[0-9]{1,3}(?:\.[0-9]+){1,2}",
                    "architecture": r"(?:arm64|x86_64)"}
        if not re.fullmatch(patterns[command_id], text.strip()):
            record["reason"] = "unexpected_version_shape"
            return record
    elif not re.search(r"\busage\s*:", text, re.I) or Path(argv[0]).name not in text:
        record["reason"] = "unrecognized_help_shape"
        return record
    record.update(status="captured", reason=None, text=text,
                  textSHA256=hashlib.sha256(data).hexdigest())
    return record


def tool_identity(path):
    """Fingerprint only fixed OS binaries; never retain bytes or identity metadata."""
    if path not in {argv[0] for argv in COMMANDS.values()}:
        raise ValueError("unreviewed tool identity")
    result = {"path": path, "standaloneVersion": None,
              "versionSource": "recorded macOS product/build and binary SHA-256",
              "sha256": None, "status": "inconclusive"}
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= BINARY_LIMIT_BYTES:
                return result
            # Bounded to the validated binary size; no user files or signatures are read.
            data = stream.read(before.st_size + 1)
            after = os.fstat(stream.fileno())
            if len(data) != before.st_size or (before.st_ino, before.st_size, before.st_mtime_ns) != (
                    after.st_ino, after.st_size, after.st_mtime_ns):
                return result
            result.update(sha256=hashlib.sha256(data).hexdigest(), status="fingerprinted")
    except OSError:
        pass
    return result


class ManualRejected(ValueError):
    """A fixed, content-free reason; never use native exception text."""


def manual_capture(source_id):
    tool, path, compression = MANUAL_SOURCES[source_id]
    record = {"id": source_id, "tool": tool, "path": path,
              "compression": compression, "format": "roff-source", "encoding": "utf-8",
              "sourceByteLimit": MANUAL_SOURCE_LIMIT, "decodedByteLimit": MANUAL_TEXT_LIMIT,
              "deadlineSeconds": TIMEOUT_SECONDS, "status": "inconclusive",
              "reason": "source_unavailable", "text": None}
    deadline = time.monotonic() + TIMEOUT_SECONDS
    descriptors = []
    def remaining():
        if time.monotonic() >= deadline:
            raise ManualRejected("manual_timeout")
    def checked_open(component, parent=None, directory=False):
        remaining()
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        if directory:
            flags |= os.O_DIRECTORY
        fd = os.open(component, flags, **({"dir_fd": parent} if parent is not None else {}))
        descriptors.append(fd)
        info = os.fstat(fd)
        expected = stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode)
        if not expected or info.st_uid != 0 or info.st_mode & 0o022:
            raise ManualRejected("unsafe_manual_source")
        return fd, info
    try:
        # Walk only literal fixed system components, anchored to open descriptors.
        # No realpath, MANPATH, home directory, glob, directory listing or man tool.
        parent, _ = checked_open("/", directory=True)
        parts = path.split("/")[1:]
        for part in parts[:-1]:
            parent, _ = checked_open(part, parent, directory=True)
        fd, before = checked_open(parts[-1], parent)
        if not 0 < before.st_size <= MANUAL_SOURCE_LIMIT:
            raise ManualRejected("manual_source_size")
        data = bytearray()
        while True:
            remaining()
            chunk = os.read(fd, min(4096, MANUAL_SOURCE_LIMIT + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > MANUAL_SOURCE_LIMIT:
                raise ManualRejected("manual_source_size")
        after = os.fstat(fd)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (len(data) != before.st_size or
                any(getattr(before, name) != getattr(after, name) for name in fields)):
            raise ManualRejected("manual_changed_during_read")
        remaining()
        raw = bytes(data)
        if compression == "gzip":
            decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
            decoded = decoder.decompress(raw, MANUAL_TEXT_LIMIT + 1)
            if len(decoded) > MANUAL_TEXT_LIMIT or decoder.unconsumed_tail:
                raise ManualRejected("manual_expansion_limit")
            if not decoder.eof or decoder.unused_data:
                raise ManualRejected("unsupported_gzip_stream")
        else:
            decoded = raw
        remaining()
        if not decoded or len(decoded) > MANUAL_TEXT_LIMIT:
            raise ManualRejected("manual_expansion_limit")
        text = decoded.decode("utf-8", errors="strict")
        if any(unicodedata.category(c) in {"Cc", "Cf", "Cs"} and c not in "\t\r\n" for c in text):
            raise ManualRejected("invalid_manual_text")
        # Accept a section-1 roff source for this exact tool, never a redirect or
        # guessed rendered page. Roff is retained as inert text, not interpreted.
        title = r'^\.Dt\s+"?' + re.escape(tool) + r'"?\s+1(?:\s|$)'
        if (not re.search(title, text, re.M | re.I) or
                not re.search(r'^\.Sh\s+"?NAME"?\s*$', text, re.M | re.I) or
                not re.search(r'^\.Sh\s+"?SYNOPSIS"?\s*$', text, re.M | re.I)):
            raise ManualRejected("unrecognized_manual_shape")
        record.update(status="captured", reason=None, text=text,
                      sourceBytes=len(raw), decodedBytes=len(decoded),
                      sourceSHA256=hashlib.sha256(raw).hexdigest(),
                      textSHA256=hashlib.sha256(decoded).hexdigest(),
                      descriptorRootOwnedChecks=True)
    except ManualRejected as error:
        record["reason"] = str(error)  # Only the fixed reasons above.
    except UnicodeDecodeError:
        record["reason"] = "invalid_manual_text"
    except zlib.error:
        record["reason"] = "invalid_gzip_stream"
    except OSError:
        pass  # No exception text, errno-derived permission claim or data fallback.
    finally:
        for fd in reversed(descriptors):
            os.close(fd)
    return record


def summarize_coverage(result):
    by_id = {row["id"]: row for row in result["commands"]}
    provenance = (all(by_id.get(name, {}).get("status") == "captured" for name in VERSION_IDS) and
                  len(result["tools"]) == 4 and
                  all(row["status"] == "fingerprinted" for row in result["tools"]))
    manuals = {tool: any(row["tool"] == tool and row["status"] == "captured"
                         for row in result["manuals"]) for tool in ("launchctl", "log")}
    help_ids = [name for name in COMMANDS if name not in VERSION_IDS]
    help_captured = [name for name in help_ids if by_id.get(name, {}).get("status") == "captured"]
    result["coverage"] = {"requiredProvenanceCaptured": provenance,
                          "installedManualCaptured": manuals,
                          "helpCaptured": help_captured,
                          "helpInconclusive": [name for name in help_ids if name not in help_captured],
                          "requestedHelpCoverage": "complete" if len(help_captured) == len(help_ids) else "partial"}
    acquired = provenance and all(manuals.values())
    result["result"] = "documentation_acquired" if acquired else "inconclusive"
    result["coverage"]["requestedDocumentationCoverage"] = (
        "complete" if acquired and len(help_captured) == len(help_ids) else "partial")


def collect(context):
    result = {"schemaVersion": 2, "scope": "builtin-help-and-installed-manuals-only",
              "context": context, "sourceFiles": {}, "commands": [], "tools": [], "manuals": [],
              "result": "inconclusive", "nativeAcceptance": False,
              "logVisibilityEstablished": False, "logSchemaEstablished": False,
              "launchdBindingEstablished": False}
    for relative in SOURCE_PATHS:
        result["sourceFiles"][relative] = hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
    for command_id in VERSION_IDS:
        result["commands"].append(capture(command_id))
    if any(row["status"] != "captured" for row in result["commands"]):
        summarize_coverage(result)
        return result
    if result["commands"][3]["text"].strip() != context["expectedMachine"]:
        result["reason"] = "native_architecture_mismatch"
        summarize_coverage(result)
        return result
    for path in sorted({argv[0] for argv in COMMANDS.values()}):
        result["tools"].append(tool_identity(path))
    # Both tools receive only the help verb, never an operational verb or target.
    for command_id in COMMANDS:
        if command_id not in VERSION_IDS:
            result["commands"].append(capture(command_id))
    for source_id in MANUAL_SOURCES:
        result["manuals"].append(manual_capture(source_id))
    summarize_coverage(result)
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="check fixed command/manual selections without execution")
    args = parser.parse_args(argv)
    check_commands()
    if args.check:
        print("Verified 10 fixed commands and 4 fixed manual paths; no commands or manual reads executed.")
        return 0
    context = hosted_context(os.environ, sys.platform)
    # Refuse to overwrite previous evidence, including symlinks.
    if DESTINATION.exists() or DESTINATION.is_symlink():
        raise ValueError("documentation evidence already exists")
    result = collect(context)
    DESTINATION.parent.mkdir(parents=True, exist_ok=True)
    with DESTINATION.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    print("Documentation evidence recorded: " + result["result"] + ". No log or service read was attempted.")
    return 0 if result["result"] == "documentation_acquired" else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError):
        print("Documentation collection refused or failed; no host-data fallback.", file=sys.stderr)
        sys.exit(1)
