#!/usr/bin/env python3
"""Build-time data conversion only. Does not execute the native adapter."""
from pathlib import Path
import sys
source = Path(__file__).resolve().parent.parent / "config.template"
text = source.read_text()
assert ')TRACEBOLT"' not in text
Path(sys.argv[1]).write_text('static constexpr char kConfigTemplate[] = R"TRACEBOLT(' + text + ')TRACEBOLT";\n')
