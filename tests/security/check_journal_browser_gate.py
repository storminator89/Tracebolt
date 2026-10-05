"""Check the seven fixed synthetic browser cases without printing report contents."""
import json
import os
import re
import stat
import sys

from report_complete_mvp import unique_object, reject_constant

MAX_BYTES = 131072
CASES = {
    'Explicit content and HTTP acknowledgements gate one lazy journal request and honest pending state',
    'Source guidance and recognizable search shortcuts never expand local journal permission',
    'Complete and partial invented messages render inertly with honest English and German mobile coverage',
    'Literal case-insensitive captured-snapshot search and hundred-row pages preserve digest and original times',
    'Cancel clears rows immediately and a lost committed response reconciles without mutation replay',
    'Visibility restoration revalidates cleared content and expiry remains fifteen minutes from creation',
    'Device navigation discards held journal pages and real operator logout removes private content',
}
FLAGS = {
    'secretsExported',
    'realTelemetryExported',
    'hostJournalRead',
    'helperExecuted',
    'permissionChanges',
    'collectorExecuted',
    'installerExecuted',
    'userVmAccessed',
}
TEXT = {"createdAt", "scope", "fixture", "faultInjection", "existingGate"}
KEYS = FLAGS | TEXT | {"sourceSha", "runtimeErrorCount", "results", "summary"}


def validate(value, source_sha):
    if not isinstance(source_sha, str) or re.fullmatch(r"[0-9a-f]{40}", source_sha) is None:
        raise ValueError("invalid expected source")
    if not isinstance(value, dict) or set(value) != KEYS or value["sourceSha"] != source_sha:
        raise ValueError("invalid report identity or shape")
    if any(value[key] is not False for key in FLAGS):
        raise ValueError("invalid execution/export scope")
    if any(not isinstance(value[key], str) or not 0 < len(value[key]) <= 2048 for key in TEXT):
        raise ValueError("invalid report metadata")
    if type(value["runtimeErrorCount"]) is not int or value["runtimeErrorCount"] != 0:
        raise ValueError("runtime errors")
    summary = value["summary"]
    if not isinstance(summary, dict) or set(summary) != {"passed", "failed", "setupFailure"}:
        raise ValueError("invalid summary")
    if type(summary["passed"]) is not int or summary["passed"] != 7 or type(summary["failed"]) is not int or summary["failed"] != 0 or summary["setupFailure"] is not False:
        raise ValueError("incomplete summary")
    results = value["results"]
    if not isinstance(results, list) or len(results) != 7:
        raise ValueError("wrong case count")
    names = set()
    for result in results:
        if not isinstance(result, dict) or set(result) != {"name", "status", "durationMs"}:
            raise ValueError("invalid result shape")
        name = result["name"]
        if not isinstance(name, str) or name not in CASES or name in names or result["status"] != "PASS":
            raise ValueError("invalid case")
        if type(result["durationMs"]) is not int or not 0 <= result["durationMs"] <= 600000:
            raise ValueError("invalid duration")
        names.add(name)
    if names != CASES:
        raise ValueError("missing case")


def read_report(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BYTES:
            raise ValueError("invalid report file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(MAX_BYTES + 1)
        if not 0 < len(raw) <= MAX_BYTES:
            raise ValueError("invalid report bounds")
        return json.loads(raw, object_pairs_hook=unique_object, parse_constant=reject_constant)
    finally:
        os.close(fd)


def main(argv):
    try:
        if len(argv) != 2:
            raise ValueError("invalid arguments")
        validate(read_report(argv[1]), os.environ.get("TRACEBOLT_SOURCE_SHA"))
    except Exception:
        print("FAIL: missing, partial, mismatched or unsafe journal-browser evidence.")
        return 1
    print("PASS: seven exact journal browser cases on the selected commit; invented data and no host journal, helper, permission, collector, installer or user-VM execution.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
