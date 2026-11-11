#!/usr/bin/env python3
"""Change ONLY an isolated ignored PS5LM Plus fork's title identity for a safe PS5 test.

Runs before the title build. Requires an explicit --test-title-id, refuses the
upstream title identity and refuses tracked or non-forked source repositories.
The PS5's `/data/PS5LM` state is still shared; back it up separately.
"""
import argparse
import json
import pathlib
import re
import sys

ORIGINAL = 'PPSA99581'

def prepare(repo: pathlib.Path, test_id: str) -> dict:
    if not re.fullmatch(r'PPSA[0-9]{5}', test_id) or test_id == ORIGINAL:
        raise ValueError('provide a distinct, well-formed test title ID (not the original)')
    repo = repo.resolve(strict=True)
    if repo.name.startswith('.') or repo == pathlib.Path.cwd().resolve():
        raise ValueError('refusing current/original repository')
    # Restrict to the intentionally isolated generated clone under build/.
    if not (repo.parent.name == 'build' and repo.name.startswith('ps5lm-nexus-')):
        raise ValueError('target must be a generated build/ps5lm-nexus-* test clone')
    script = repo / 'scripts/build-app.sh'
    target = repo / 'ps5/app/sce_sys/param.json'
    if not script.is_file() or not target.is_file() or target.is_symlink():
        raise ValueError('not a PS5LM Plus native title clone')
    meta = json.loads(target.read_text())
    if meta.get('titleId') not in (ORIGINAL, test_id):
        raise ValueError('unexpected input title ID; refuse to rewrite')
    meta['titleId'] = test_id
    meta['conceptId'] = test_id[4:]
    meta['contentId'] = f'UP9000-{test_id}_00-NEXUSPS5LM000001'
    meta.setdefault('localizedParameters', {}).setdefault('en-US', {})['titleName'] = 'NexusAI Test (PS5LM)'
    if len(meta['contentId']) != 36:
        raise ValueError('incorrect contentId length')
    target.write_text(json.dumps(meta, indent=2) + '\n')
    return {k: meta[k] for k in ('titleId', 'contentId', 'conceptId')}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('clone', type=pathlib.Path)
    parser.add_argument('--test-title-id', required=True, help='distinct ID confirmed unused on your PS5')
    args = parser.parse_args()
    print(json.dumps(prepare(args.clone, args.test_title_id), indent=2))

if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, json.JSONDecodeError) as error:
        print('Refusing test title identity change:', error, file=sys.stderr)
        sys.exit(1)
