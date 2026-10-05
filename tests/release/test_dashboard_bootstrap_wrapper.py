"""Local inert execution-tail checks. No download, real bootstrap or installer.

Only an unprivileged temporary fixture program executes. The production pin is
unchanged. These checks establish fd/terminal/signal handoff, not service acceptance.
"""
import ast
import hashlib
import json
import os
from pathlib import Path
import select
import shlex
import signal
import subprocess
import sys
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[2] / "web/src/verified-download-command.ts"


def execution_tail():
    """Use the exact source-owned tail, never the download or root/apply flow."""
    lines = SOURCE.read_text().splitlines()
    first = lines.index('        \'exec 3< "$stage/bootstrap.py"\',')
    tail = [ast.literal_eval(line.strip().removesuffix(",")) for line in lines[first:first + 4]]
    final = lines[first + 4].strip()
    assert final == '`exec python3 -I -B /proc/self/fd/3 --action install --apply --pending-service${publicArguments}`,'
    tail.append(final[1:-2].replace("${publicArguments}", ""))
    assert "    ].join('; ');" in lines
    return "; ".join(tail)


@unittest.skipUnless(sys.platform == "linux" and Path("/proc/self/fd").is_dir(), "Linux proc-fd fixture")
class DashboardExecutionTail(unittest.TestCase):
    def test_verified_inode_terminal_and_direct_signals(self):
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=signum.name), tempfile.TemporaryDirectory(prefix="tracebolt-inert-tail-") as temp:
                stage = Path(temp) / "stage"
                stage.mkdir(mode=0o700)
                path = stage / "bootstrap.py"
                # Ignores all command arguments. This is invented fixture code,
                # not an import or execution of the real release bootstrap.
                contents = ("import hashlib, json, os, signal, sys\n"
                            "def stop(signum, frame):\n"
                            "    print(json.dumps({'signal': signum}), flush=True)\n"
                            "    raise SystemExit(128 + signum)\n"
                            "for signum in (signal.SIGINT, signal.SIGTERM):\n"
                            "    signal.signal(signum, stop)\n"
                            "with open(__file__, 'rb') as stream:\n"
                            "    digest = hashlib.sha256(stream.read()).hexdigest()\n"
                            "print(json.dumps({'pid': os.getpid(), 'tty': os.isatty(0), "
                            "'fdInode': os.fstat(3).st_ino, 'executedInode': os.stat(__file__).st_ino, "
                            f"'stagingRemoved': not os.path.exists({str(stage)!r}), 'sha256': digest}}), flush=True)\n"
                            "while True:\n"
                            "    signal.pause()\n").encode()
                path.write_bytes(contents)
                path.chmod(0o600)
                inode = path.stat().st_ino
                digest = hashlib.sha256(contents).hexdigest()
                script = ("set -eu; umask 077; " + f"stage={shlex.quote(str(stage))}; " +
                          f"printf '%s  %s\\n' {shlex.quote(digest)} \"$stage/bootstrap.py\" | sha256sum --check --status; " +
                          execution_tail())
                self.assertNotRegex(script, r"[\r\n]")
                master, terminal = os.openpty()
                child = None
                try:
                    child = subprocess.Popen(["/bin/sh", "-c", script], stdin=terminal, stdout=subprocess.PIPE,
                                             stderr=subprocess.PIPE, text=True,
                                             env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C.UTF-8"})
                    self.assertTrue(select.select([child.stdout], [], [], 5)[0], "inert fixture did not become ready")
                    ready = json.loads(child.stdout.readline())
                    self.assertEqual(ready, {"pid": child.pid, "tty": True, "fdInode": inode,
                                             "executedInode": inode, "stagingRemoved": True, "sha256": digest})
                    # Target only the original shell PID. Exec must have replaced
                    # it, with no outer wrapper to intercept/delay these signals.
                    os.kill(child.pid, signum)
                    stdout, stderr = child.communicate(timeout=5)
                    self.assertEqual(stderr, "")
                    if signum == signal.SIGHUP:
                        self.assertEqual(child.returncode, -signal.SIGHUP)
                        self.assertEqual(stdout, "")  # Existing default, not new HUP forwarding.
                    else:
                        self.assertEqual(child.returncode, 128 + signum)
                        self.assertEqual(json.loads(stdout), {"signal": signum})
                    self.assertFalse(stage.exists())
                finally:
                    os.close(master)
                    os.close(terminal)
                    if child is not None:
                        if child.poll() is None:
                            child.kill()  # Only this inert, child-free test fixture.
                        child.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
