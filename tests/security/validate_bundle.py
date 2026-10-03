#!/usr/bin/env python3
"""Validate one CLI support bundle without printing its telemetry or identifiers."""
from __future__ import annotations

import argparse
from datetime import datetime
import re
import json
from pathlib import Path
import sys

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import ValidationError

MAX_BYTES = 65_536
SCHEMA_VERSION = "tracebolt.support.v1"
# jsonschema installs date-time support only with optional extras. Register a
# dependency-free strict checker for the RFC3339 timestamp subset emitted by Go.
TIMESTAMP = re.compile(r"^\d{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])[Tt](?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?(?:[Zz]|[+-](?:[01]\d|2[0-3]):[0-5]\d)$")
FORMAT_CHECKER = FormatChecker()


@FORMAT_CHECKER.checks("date-time", raises=(ValueError, OverflowError))
def valid_timestamp(value):
    if not isinstance(value, str):
        return True  # The schema checks the type independently.
    if not TIMESTAMP.fullmatch(value):
        return False
    parsed = datetime.fromisoformat(value.replace("t", "T").replace("z", "+00:00").replace("Z", "+00:00"))
    return parsed.tzinfo is not None



def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def reject_constant(_value):
    raise ValueError("non-finite JSON numeric constant")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def validate(raw: bytes, expected_platform: str) -> None:
    require(0 < len(raw) <= MAX_BYTES, "serialized bundle exceeds the 64 KiB limit or is empty")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique_object,
                       parse_constant=reject_constant)
    schema_path = Path(__file__).resolve().parents[2] / "docs" / "support-bundle.schema.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema, format_checker=FORMAT_CHECKER).validate(value)
    require(value["schemaVersion"] == SCHEMA_VERSION, "unexpected schema version")
    require(value["product"] == "Tracebolt" and bool(value["version"]), "missing product version")
    observation = value["observation"]
    require(value["platform"] == observation["platform"] == expected_platform,
            "unexpected or inconsistent platform")
    roles = {
        "linux": ("sandbox-local", "sandbox", "Local sandbox", "Cloud sandbox"),
        "windows": ("local-windows", "local", "Local Windows", "Local machine"),
        "macos": ("local-macos", "local", "Local macOS", "Local machine"),
    }
    role = roles[expected_platform]
    require(tuple(observation[k] for k in ("id", "source", "name", "site")) == role,
            "fixed role fields were changed or repurposed as identifiers")
    require(observation["group"] == "Local observations", "unexpected role group")
    require(observation["status"] == "unknown" and observation["ip"] is None
            and observation["synthetic"] is False, "unsafe health or identity metadata")
    require(not observation["trend"] and not observation["caseIds"],
            "unexpected invented history or case association")
    allowed_tags = {"read-only", "local-only", "sandbox" if expected_platform == "linux"
                    else "native-unverified"}
    require(set(observation["tags"]) <= allowed_tags, "unapproved free-form role tag")
    evidence_ids = [item["id"] for item in observation["evidence"]]
    require(all(evidence_ids) and len(evidence_ids) == len(set(evidence_ids)),
            "missing or duplicate evidence identity")
    for key in ("cpu", "memory", "disk"):
        metric = observation[key]
        if metric["quality"] == "healthy":
            require(metric["value"] is not None, "valid metric quality requires a value")
        if metric["quality"] in ("unknown", "denied"):
            require(metric["value"] is None, "unavailable metric must not contain a value")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", nargs="?", default="-", help="JSON file or - for stdin")
    parser.add_argument("--expect-platform", choices=("linux", "windows", "macos"), default="linux")
    args = parser.parse_args()
    try:
        if args.bundle == "-":
            raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        else:
            with open(args.bundle, "rb") as stream:
                raw = stream.read(MAX_BYTES + 1)
        validate(raw, args.expect_platform)
    except ValidationError:
        # jsonschema's full exception can echo instance values; never print it.
        print("FAIL: support bundle does not match the committed JSON schema.", file=sys.stderr)
        return 1
    except (ValueError, UnicodeError, OSError):
        # Do not echo input, file paths, or telemetry, including malformed input.
        print("FAIL: support bundle encoding, bounds, version or privacy metadata is invalid.", file=sys.stderr)
        return 1
    print(f"PASS: {args.expect_platform} CLI support bundle schema, 64 KiB cap, version and privacy metadata.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
