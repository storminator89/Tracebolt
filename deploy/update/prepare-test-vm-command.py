#!/usr/bin/env python3
"""Render one reviewed public command; never downloads or runs an updater."""
import argparse
import hashlib
from pathlib import Path
import re
import shlex


def command(updater_commit, manager_commit, manager_tree):
    for value in (updater_commit, manager_commit, manager_tree):
        if not re.fullmatch(r"[0-9a-f]{40}", value):
            raise ValueError("Every revision must be a full reviewed lowercase Git SHA.")
    checksum = hashlib.sha256(Path(__file__).with_name("test-vm.py").read_bytes()).hexdigest()
    url = "https://raw.githubusercontent.com/storminator89/Tracebolt/" + updater_commit + "/deploy/update/test-vm.py"
    parts = [
        "set -eu", "umask 077",
        '[ "$(id -u)" -eq 0 ] && [ -t 0 ] || { printf "%s\\n" "Use the existing test VM root terminal." >&2; exit 1; }',
        'for tool in curl sha256sum python3 mktemp rm rmdir; do command -v "$tool" >/dev/null || { printf "%s\\n" "Missing prerequisite: $tool; nothing installed." >&2; exit 1; }; done',
        'stage=$(mktemp -d /tmp/tracebolt-update.XXXXXXXXXX)',
        'trap ' + shlex.quote('status=$?; trap - 0; rm -f -- "$stage/update.py"; rmdir -- "$stage"; exit "$status"') + ' 0',
        "trap 'exit 129' HUP", "trap 'exit 130' INT", "trap 'exit 143' TERM",
        'status=$(curl -q --fail --silent --show-error --proto =https --proto-redir =https --proxy "" --noproxy "*" --max-redirs 0 --connect-timeout 10 --max-time 60 --max-filesize 131072 --output "$stage/update.py" --write-out "%{http_code}" ' + shlex.quote(url) + ')',
        '[ "$status" = 200 ] || { printf "%s\\n" "Updater download did not return HTTP 200." >&2; exit 1; }',
        'printf "%s  %s\\n" ' + checksum + ' "$stage/update.py" | sha256sum --check --status || { printf "%s\\n" "Updater SHA-256 mismatch; nothing executed." >&2; exit 1; }',
        'exec 3< "$stage/update.py"', 'rm -f -- "$stage/update.py"', 'rmdir -- "$stage"', 'trap - 0 HUP INT TERM',
        'exec python3 -I -B /proc/self/fd/3 --manager-commit ' + manager_commit + ' --manager-tree ' + manager_tree + ' --apply',
    ]
    return "/usr/bin/env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 /bin/sh -c " + shlex.quote("; ".join(parts))


def main():
    parser = argparse.ArgumentParser(allow_abbrev=False, description=__doc__)
    parser.add_argument("--updater-commit", required=True)
    parser.add_argument("--manager-commit", required=True)
    parser.add_argument("--manager-tree", required=True)
    args = parser.parse_args()
    print(command(args.updater_commit, args.manager_commit, args.manager_tree))


if __name__ == "__main__":
    main()
