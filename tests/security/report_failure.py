#!/usr/bin/env python3
"""Emit stage/test/source-line metadata only; never emit raw runtime output."""
import argparse
from pathlib import Path
import re

STAGES = ('api','http','ai','managed_startup','managed','sqlite','transport','go')
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--stage', choices=STAGES, required=True)
parser.add_argument('log', type=Path)
args = parser.parse_args()
try:
    with args.log.open('rb') as stream:
        raw = stream.read(8 * 1024 * 1024)
    text = raw.decode('utf-8', errors='replace')
except OSError:
    text = ''
# Forward only this tool's exact, constrained metadata format from nested checks.
safe = re.compile(r'^SAFE_FAILURE stage=(?:'+ '|'.join(STAGES) +r') source=(?:none|run_boundary\.py|run_ai_boundary\.py|run_telemetry_boundary\.py|run_transport_smoke\.py) line=\d{1,6} test=(?:none|test_[a-zA-Z0-9_]{1,120})$')
for line in text.splitlines():
    if safe.fullmatch(line):
        print(line)
        raise SystemExit(0)
stage = args.stage
for match in re.finditer(r'^TRACEBOLT_STAGE=('+'|'.join(STAGES)+r')$', text, re.M):
    stage = match.group(1)
source, number, test = 'none', '0', 'none'
for match in re.finditer(r'File "[^"\n]*(run_boundary\.py|run_ai_boundary\.py|run_telemetry_boundary\.py|run_transport_smoke\.py)", line (\d{1,6})',text):
    source, number = match.groups()
for match in re.finditer(r'^(?:FAIL|ERROR): (test_[a-zA-Z0-9_]{1,120}) \(',text,re.M):
    test = match.group(1)
print(f'SAFE_FAILURE stage={stage} source={source} line={number} test={test}')
