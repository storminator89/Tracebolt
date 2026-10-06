"""Require actual service-process action-identity reads; never print raw logs."""
import io
import re
import sys

from report_go_failure import decode, read_private, validate_event

PACKAGE = "localrmm/internal/lanclient"
COMPLETE = "TestActionSetupIdentityLocalCompleteAndNoWrites"
MISSING = "TestActionSetupIdentityRejectsMissingActivationOrLedgers"
LOCKED = "TestActionSetupIdentityWorksWhileSenderOwnsAllLedgers"
EVIDENCE = {
    COMPLETE + "/tls": "accepted",
    COMPLETE + "/http-test": "accepted",
    LOCKED: "accepted",
    **{MISSING + "/" + path: "state_rejected" for path in (
        "ready.json", "state/state.json", "state/inventory", "state/system")},
}
REQUIRED = {COMPLETE, MISSING, *EVIDENCE}
MARKER = re.compile(r"    action_setup_linux_test.go:[1-9][0-9]*: "
                    r"action setup identity: public_reader=(accepted|state_rejected)\n")
MAX_FILE = 4 * 1024 * 1024
MAX_LINE = 64 * 1024
MAX_EVENTS = 10000


def validate(raw):
    if not raw or len(raw) > MAX_FILE or not raw.endswith(b"\n"):
        raise ValueError("invalid log bounds")
    started, passed, evidence = set(), set(), set()
    package_passed = False
    for count, line in enumerate(io.BytesIO(raw), 1):
        if count > MAX_EVENTS or len(line) > MAX_LINE:
            raise ValueError("invalid log bounds")
        event = decode(line)
        validate_event(event)
        action, test = event["Action"], event.get("Test")
        if action in {"fail", "build-fail", "skip"}:
            raise ValueError("failed or skipped event")
        if event.get("Package") != PACKAGE or package_passed:
            raise ValueError("unexpected package or trailing event")
        if test is not None:
            if test not in REQUIRED:
                raise ValueError("unexpected test")
            if action == "run":
                if test in started:
                    raise ValueError("duplicate run")
                started.add(test)
            if action == "output":
                marker = MARKER.fullmatch(event.get("Output", ""))
                if marker:
                    if (test not in started or test in passed or test in evidence
                            or EVIDENCE.get(test) != marker[1]):
                        raise ValueError("invalid evidence")
                    evidence.add(test)
            if action == "pass":
                children = {name for name in REQUIRED if name.startswith(test + "/")}
                if (test not in started or test in passed or not children <= passed
                        or (test in EVIDENCE and test not in evidence)):
                    raise ValueError("incomplete test")
                passed.add(test)
        elif action == "pass":
            if passed != REQUIRED:
                raise ValueError("incomplete package")
            package_passed = True
    if started != REQUIRED or passed != REQUIRED or evidence != set(EVIDENCE) or not package_passed:
        raise ValueError("incomplete result")


def main(argv):
    try:
        if len(argv) != 2:
            raise ValueError("invalid arguments")
        validate(read_private(argv[1], MAX_FILE))
    except Exception:
        print("FAIL: missing, skipped or invalid action-setup service-identity evidence.")
        return 1
    print("PASS: actual nonroot service-identity reads for TLS, HTTP-test and sender-owned ledgers; missing activation/ledgers rejected; no fixture writes or manager requests.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
