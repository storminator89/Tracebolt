#!/usr/bin/env python3
"""Deterministic, unsigned review evidence for an existing Linux candidate.

Inspect Go build metadata without executing a candidate binary. This is not an
attestation verifier, release publisher, complete source SBOM or runtime gate.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tarfile
from urllib.parse import quote

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("evidence_bootstrap", HERE / "linux-bootstrap.py")
b = importlib.util.module_from_spec(spec)
spec.loader.exec_module(b)
MAX_METADATA = 1024 * 1024
MODULE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._~+/-]{0,239}\Z")
MODULE_VERSION = re.compile(r"v[0-9][A-Za-z0-9.+-]{0,127}\Z")
SUM = re.compile(r"h1:[A-Za-z0-9+/]{43}=\Z")


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def parse(raw):
    b.require(0 < len(raw) <= MAX_METADATA, "Evidence metadata size rejected.")
    return json.loads(raw.decode("utf-8"), object_pairs_hook=b.unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(b.Rejected("Invalid JSON number.")))


def protected(path, limit):
    metadata = path.lstat()
    b.require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_uid == os.geteuid() and
              not stat.S_IMODE(metadata.st_mode) & 0o022 and 0 < metadata.st_size <= limit,
              "Candidate file protection or size rejected.")
    return metadata


def checked_asset(path, entry):
    metadata = protected(path, b.MAX_SOURCE if path.name.endswith("-source.tar") else b.MAX_BINARY)
    b.require(metadata.st_size == entry["size"] and b.file_digest(path) == entry["sha256"],
              "Candidate bytes do not match their manifest.")
    return metadata


def archived_locks(source):
    """Read only two fixed, bounded regular files; never extract archive paths."""
    locks = {}
    with tarfile.open(source, mode="r|") as archive:
        for member in archive:
            if member.name not in {"go.mod", "go.sum"}:
                continue
            b.require(member.name not in locks and member.isfile() and 0 < member.size <= MAX_METADATA,
                      "Source dependency locks are missing, duplicated or unsupported.")
            locks[member.name] = archive.extractfile(member).read(MAX_METADATA + 1)
    b.require(set(locks) == {"go.mod", "go.sum"}, "Source dependency locks are missing.")
    go_versions = re.findall(r"^go ([0-9]+\.[0-9]+\.[0-9]+)$", locks["go.mod"].decode("utf-8"), re.MULTILINE)
    b.require(len(go_versions) == 1 and re.search(r"^module localrmm$", locks["go.mod"].decode("utf-8"), re.MULTILINE),
              "Source Go version or module is unsupported.")
    sums = {}
    for line in locks["go.sum"].decode("utf-8").splitlines():
        parts = line.split()
        b.require(len(parts) == 3 and SUM.fullmatch(parts[2]), "Source module checksum rejected.")
        key = tuple(parts[:2])
        b.require(key not in sums, "Duplicate source module checksum rejected.")
        sums[key] = parts[2]
    return "go" + go_versions[0], sums, {
        name: {"sha256": b.digest(raw), "size": len(raw)} for name, raw in sorted(locks.items())}


def inspect(path):
    # 'go version' parses bytes; no candidate program is executed, no dependency
    # is fetched, and ambient workspace/toolchain selection is disabled.
    env = dict(os.environ, GOTOOLCHAIN="local", GOWORK="off", GOENV="off", GOFLAGS="", GOPROXY="off", GOSUMDB="off")
    result = subprocess.run(["go", "version", "-m", "-json", str(path)], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True, timeout=30)
    return parse(result.stdout)


def sbom(info, name, entry, version, source_commit, go_version, sums):
    prefix = f"tracebolt-{version}-linux-"
    b.require(name.startswith(prefix), "Binary asset identity rejected.")
    arch, separator, role = name[len(prefix):].partition("-")
    b.require(separator and arch in b.ARCHES and role in b.ROLES, "Binary asset target rejected.")
    b.require(type(info) is dict and info.get("GoVersion") == go_version and
              info.get("Path") == "localrmm/cmd/" + role,
              "Binary toolchain or command identity rejected.")
    main = info.get("Main")
    main_version = main.get("Version") if type(main) is dict else None
    b.require(type(main) is dict and main.get("Path") == "localrmm" and type(main_version) is str and
              (main_version == "(devel)" or MODULE_VERSION.fullmatch(main_version)) and
              not main.get("Replace"), "Binary main module identity rejected.")
    rows = info.get("Settings")
    b.require(type(rows) is list and all(type(row) is dict and set(row) == {"Key", "Value"} and
              type(row["Key"]) is str and type(row["Value"]) is str for row in rows), "Binary settings rejected.")
    settings = {row["Key"]: row["Value"] for row in rows}
    b.require(len(settings) == len(rows), "Duplicate binary setting rejected.")
    required = {"GOOS": "linux", "GOARCH": arch, "CGO_ENABLED": "0", "-trimpath": "true",
                "vcs": "git", "vcs.revision": source_commit, "vcs.modified": "false",
                "GOAMD64" if arch == "amd64" else "GOARM64": "v1" if arch == "amd64" else "v8.0"}
    b.require(all(settings.get(key) == value for key, value in required.items()), "Binary build/source settings rejected.")
    deps = info.get("Deps", [])
    b.require(type(deps) is list and len(deps) <= 1024, "Binary dependency count rejected.")
    components = []
    seen = set()
    for dependency in deps:
        b.require(type(dependency) is dict, "Binary dependency rejected.")
        path, dep_version, checksum = (dependency.get(key) for key in ("Path", "Version", "Sum"))
        b.require(type(path) is str and MODULE.fullmatch(path) and all(part not in {"", ".", ".."} for part in path.split("/")) and
                  type(dep_version) is str and MODULE_VERSION.fullmatch(dep_version) and type(checksum) is str and SUM.fullmatch(checksum) and
                  not dependency.get("Replace") and path not in seen and sums.get((path, dep_version)) == checksum,
                  "Binary module is unpinned, replaced, duplicated or absent from source checksums.")
        seen.add(path)
        purl = "pkg:golang/" + quote(path, safe="/") + "@" + quote(dep_version, safe="")
        components.append({"type": "library", "bom-ref": purl, "name": path, "version": dep_version, "purl": purl,
                           "properties": [{"name": "tracebolt:go:module-sum", "value": checksum}]})
    component = {"type": "application", "bom-ref": "sha256:" + entry["sha256"], "name": name, "version": version,
                 "hashes": [{"alg": "SHA-256", "content": entry["sha256"]}],
                 "properties": [{"name": key, "value": value} for key, value in sorted({
                     "tracebolt:source-commit": source_commit, "tracebolt:go:version": go_version,
                     "tracebolt:target": "linux-" + arch,
                     "tracebolt:inventory": "embedded Go modules only; no module dependency graph or license inference"}.items())]}
    # BuildInfo lists included modules, not module-to-module edges. Do not invent
    # a graph or assert source, standard-library-package or license completeness.
    return {"$schema": "http://cyclonedx.org/schema/bom-1.6.schema.json", "bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"lifecycles": [{"phase": "post-build"}], "component": component},
            "components": sorted(components, key=lambda row: row["bom-ref"]),
            "compositions": [{"aggregate": "incomplete", "assemblies": [component["bom-ref"]]}]}


def generate(candidate, output, version, source_commit, inspector=inspect):
    b.require(b.VERSION.fullmatch(version) and len(version) <= 64 and b.COMMIT.fullmatch(source_commit), "Invalid candidate identity.")
    b.require(candidate.is_absolute() and candidate == candidate.resolve() and candidate.is_dir() and
              output.is_absolute() and output == output.resolve() and not output.exists() and
              not output.is_relative_to(candidate), "Use an existing candidate and a new separate output directory.")
    manifest_path = candidate / "manifest.json"
    protected(manifest_path, b.MAX_MANIFEST)
    raw = manifest_path.read_bytes()
    # A self-hash enables the existing strict schema parser, not signature trust.
    # Actual keyless verification remains mandatory in the unmodified workflow.
    manifest = b.parse_manifest(raw, {"version": version, "sourceCommit": source_commit, "manifestSHA256": b.digest(raw)})
    for name, entry in manifest["assets"].items():
        checked_asset(candidate / name, entry)
    go_version, sums, locks = archived_locks(candidate / f"tracebolt-{version}-source.tar")
    documents, inventory = {}, {}
    for name, entry in sorted(manifest["assets"].items()):
        inventory[name] = dict(entry)
        if name.endswith("-source.tar"):
            continue
        path = candidate / name
        before = path.stat()
        document = sbom(inspector(path), name, entry, version, source_commit, go_version, sums)
        after = checked_asset(path, entry)
        b.require((before.st_dev, before.st_ino, before.st_mtime_ns) == (after.st_dev, after.st_ino, after.st_mtime_ns),
                  "Candidate changed during metadata inspection.")
        filename = name + ".cdx.json"
        documents[filename] = canonical(document)
        inventory[name]["sbom"] = {"name": filename, "sha256": b.digest(documents[filename]), "size": len(documents[filename])}
    for name, entry in manifest["assets"].items():
        checked_asset(candidate / name, entry)
    b.require(manifest_path.read_bytes() == raw, "Candidate manifest changed during inspection.")
    documents["candidate-evidence.json"] = canonical({"schema": "tracebolt.linux-candidate-evidence.v1", "repository": b.REPOSITORY,
        "version": version, "sourceCommit": source_commit, "manifestSHA256": b.digest(raw), "dependencyLocks": locks,
        "assets": inventory, "trust": "unsigned candidate review evidence; not release verification or runtime acceptance"})
    output.mkdir(mode=0o700)
    for name, document in sorted(documents.items()):
        with b.open_private(output / name) as stream:
            stream.write(document)


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--source-commit", required=True)
    args = parser.parse_args()
    generate(args.candidate.absolute(), args.output.absolute(), args.version, args.source_commit)
    print("Unsigned candidate evidence prepared. No candidate program executed and no release published.")


if __name__ == "__main__":
    try:
        main()
    except (b.Rejected, OSError, ValueError, tarfile.TarError, subprocess.SubprocessError) as error:
        raise SystemExit(str(error) if isinstance(error, b.Rejected) else "Candidate evidence failed; no release was published.") from None
