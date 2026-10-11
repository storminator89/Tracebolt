#!/usr/bin/env python3
"""Create bounded public-byte inventories only. Never runs/builds a native artifact.

Use a separate output outside the input root. Git metadata is excluded; Python caches are rejected. Source must be a clean
checkout without build outputs or dependencies;
source mode runs on Linux, retains executable bits, and binds a preprovided Git
commit object. Copy the resulting inventory and exact bytes to Windows. No Git
subprocess, configured hook, network or ambient credentials are used.
"""
from __future__ import annotations
import sys
if not sys.flags.isolated or not sys.dont_write_bytecode:
    raise SystemExit("CONTRACT_REJECTED: invoke with Python -I -B.")
import argparse
import os
from pathlib import Path
import stat
import sys
# -B prevents writes, not reads: reject cached local modules before importing.
_here = Path(__file__).resolve().parent
if sys.pycache_prefix is not None or (_here / "__pycache__").exists() or any(_here.glob("*.py[co]")):
    raise SystemExit("CONTRACT_REJECTED: cached harness modules are not allowed.")
# Explicitly compile local .py bytes: -B alone still reads caches, and normal
# imports can prefer an extension or package with the same name.
def _source_only(name):
    import types
    path = Path(__file__).resolve().parent / (name + ".py")
    if path.is_symlink() or not path.is_file():
        raise SystemExit("CONTRACT_REJECTED: harness source file unavailable.")
    existing = sys.modules.get(name)
    if existing is not None and getattr(existing, "__source_only_loaded__", False) and getattr(existing, "__file__", None) == str(path):
        return existing
    module = types.ModuleType(name); module.__file__ = str(path)
    module.__source_only_loaded__ = True; sys.modules[name] = module
    exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    return module
_source_only("contract")
from contract import Rejected, need, no_links, canonical, digest, git_object, inventory_tree, local_input_path

def inventory(root, source=False):
    root = no_links(Path(root).absolute())
    if source:
        need(os.name == "posix")
    paths = []
    for parent, dirs, files in os.walk(root, followlinks=False):
        need("__pycache__" not in dirs)
        dirs[:] = [d for d in dirs if d != ".git"]
        for d in dirs:
            no_links(Path(parent) / d)
        for f in files:
            if f == ".git": continue
            need(not f.endswith((".pyc", ".pyo")))
            paths.append(Path(parent) / f)
    need(1 <= len(paths) <= 20000)
    out = []; total = 0
    for p in sorted(paths):
        no_links(p); info = p.stat()
        need(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= 64 << 20)
        raw = p.read_bytes(); total += len(raw); need(total <= 512 << 20)
        name = p.relative_to(root).as_posix()
        mode = "100755" if info.st_mode & 0o111 else "100644"
        out.append({"path": name, "sha": git_object("blob", raw).hex(), "sha256": digest(raw), "mode": mode, "size": len(raw)})
    return out

def main():
    a = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    a.add_argument("--root", required=True); a.add_argument("--output", required=True); a.add_argument("--source", action="store_true"); a.add_argument("--commit-object")
    args = a.parse_args()
    try:
        local_input_path(args.root); local_input_path(args.output)
        if args.commit_object is not None: local_input_path(args.commit_object)
        root = no_links(Path(args.root)); output = no_links(Path(args.output))
        need(not output.is_relative_to(root) and not output.exists())
        rows = inventory(root, args.source); raw = canonical(rows)
        need(args.source == (args.commit_object is not None))
        if args.source:
            from contract import read_regular
            commit = read_regular(args.commit_object, 2 << 20)
            need(commit.startswith(("tree " + inventory_tree(rows) + "\n").encode()) and b"\n\n" in commit)
            print("commit=" + git_object("commit", commit).hex())
        with open(output, "xb") as f:
            f.write(raw)
        print("inventorySHA256=" + digest(raw)); print("tree=" + inventory_tree(rows)); print("files=" + str(len(rows)))
    except Exception:
        print("Inventory rejected; no artifact execution or acceptance established.")
        return 2
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
