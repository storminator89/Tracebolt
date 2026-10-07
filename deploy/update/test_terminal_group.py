#!/usr/bin/env python3
"""Real interactive-shell PTY regression using inert Python signal surrogates.

The actual updater's run_foreground helper is exercised. No updater main, root
operation, network, Docker, systemd, installer or release program is invoked.
"""
import json
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import sys
import tempfile
import time
import unittest

CHILD = r'''
import json, os, pathlib, signal, sys, time
root = pathlib.Path(sys.argv[1])
assert sys.stdin.isatty()
assert os.tcgetpgrp(0) == os.getpgrp()
with open('/dev/tty', 'rb', buffering=0) as terminal:
    assert terminal.isatty()
assert signal.getsignal(signal.SIGHUP) == signal.SIG_IGN
signals = []
def contain(sig, frame):
    signals.append(sig)
    (root/'started.json').write_text(json.dumps(signals))
    # A duplicate interrupt in this window would re-enter the handler.
    time.sleep(0.25)
    (root/'contained.json').write_text(json.dumps(signals))
    raise SystemExit(0)
signal.signal(signal.SIGINT, contain)
signal.signal(signal.SIGTERM, contain)
(root/'ready.json').write_text(json.dumps(dict(pid=os.getpid(), parent=os.getppid(), group=os.getpgrp(),
    session=os.getsid(0), foreground=os.tcgetpgrp(0), parentGroup=os.getpgid(os.getppid()))))
while True:
    signal.pause()
'''
PARENT = r'''
import importlib.util, json, os, pathlib, sys
root = pathlib.Path(sys.argv[2])
spec = importlib.util.spec_from_file_location('updater', sys.argv[1])
u = importlib.util.module_from_spec(spec)
spec.loader.exec_module(u)
try:
    result = u.run_foreground([sys.executable, '-I', '-B', str(root/'child.py'), str(root)],
        {'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}, ())
    (root/'parent.json').write_text(json.dumps(dict(code=result, foreground=os.tcgetpgrp(0), group=os.getpgrp())))
except BaseException as error:
    (root/'parent.json').write_text(json.dumps(dict(error=str(error))))
'''


def until(check, *, terminal=None, seconds=8):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        if terminal is not None:
            readable, _, _ = select.select([terminal], [], [], 0.02)
            if readable:
                try:
                    os.read(terminal, 65536)
                except OSError:
                    pass
        else:
            time.sleep(0.02)
    raise AssertionError("inert terminal fixture timed out")


class ForegroundProcessGroupTests(unittest.TestCase):
    def exercise(self, action):
        with tempfile.TemporaryDirectory(prefix="tracebolt-inert-pty-") as directory:
            root = Path(directory)
            (root / "child.py").write_text(CHILD)
            (root / "parent.py").write_text(PARENT)
            shell, master = pty.fork()
            if shell == 0:
                os.execve("/bin/bash", ["bash", "--noprofile", "--norc", "-i"],
                          {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "PS1": "FIXTURE> ", "LANG": "C.UTF-8"})
            groups = []
            try:
                command = [sys.executable, "-I", "-B", str(root / "parent.py"),
                           str(Path(__file__).with_name("test-vm.py").resolve()), directory]
                os.write(master, (shlex.join(command) + "\n").encode())
                until(lambda: (root / "ready.json").exists(), terminal=master)
                facts = json.loads((root / "ready.json").read_text())
                groups = [facts["group"], facts["parentGroup"]]
                self.assertEqual(facts["session"], shell)
                self.assertEqual(facts["foreground"], facts["group"])
                self.assertNotEqual(facts["group"], facts["parentGroup"])
                self.assertNotEqual(facts["group"], os.getpgrp())
                if action == "close":
                    os.close(master); master = None
                elif action == "ctrl-c":
                    os.write(master, b"\x03")
                elif action == "parent-group-hup":
                    os.killpg(facts["parentGroup"], signal.SIGHUP)
                else:
                    raise AssertionError("unknown fixture action")
                until(lambda: (root / "contained.json").exists(), terminal=master)
                self.assertEqual(json.loads((root / "contained.json").read_text()),
                                 [int(signal.SIGINT if action == "ctrl-c" else signal.SIGTERM)])
                until(lambda: (root / "parent.json").exists(), terminal=master)
                outcome = json.loads((root / "parent.json").read_text())
                if action == "close":
                    self.assertEqual(outcome, {"error": "foreground-terminal-unavailable-after-upgrade"})
                else:
                    self.assertEqual(outcome["code"], 0)
                    self.assertEqual(outcome["foreground"], outcome["group"])
            finally:
                # These are exclusively this test's own inert process groups.
                for group in groups:
                    if group > 0 and group not in (os.getpgrp(), shell):
                        try: os.killpg(group, signal.SIGKILL)
                        except ProcessLookupError: pass
                if master is not None:
                    os.close(master)
                try: os.kill(shell, signal.SIGHUP)
                except ProcessLookupError: pass
                until(lambda: os.waitpid(shell, os.WNOHANG)[0])

    def test_terminal_close_contains_in_interactive_shell_three_trials(self):
        for _ in range(3):
            with self.subTest(trial=_):
                self.exercise("close")

    def test_real_terminal_ctrl_c_is_delivered_once(self):
        self.exercise("ctrl-c")

    def test_shell_tracked_parent_group_hup_is_forwarded_once(self):
        self.exercise("parent-group-hup")


if __name__ == "__main__":
    unittest.main()
