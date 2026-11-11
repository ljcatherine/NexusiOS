#!/usr/bin/env python3
"""Clear local inference quarantine after independent confirmation of PS5 idleness."""
import argparse
from pathlib import Path

from run_jobs import RunStore

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('state_dir', help='Existing private orchestrator state directory')
parser.add_argument('--confirmed-ps5-idle', action='store_true', required=True,
                    help='Confirm independently that the previous PS5 inference has stopped')
args = parser.parse_args()
directory = Path(args.state_dir).expanduser()
if not (directory / 'agent-runs.sqlite3').is_file():
    parser.error('state directory must contain an existing agent-runs.sqlite3')
store = RunStore(directory)
try:
    store.clear_inference_quarantine()
finally:
    store.close()
print('Inference quarantine cleared. Start the orchestrator only after verifying PS5 readiness.')
