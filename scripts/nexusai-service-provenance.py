#!/usr/bin/env python3
"""Read-only bounded Nexus service provenance; never emits env/argv/source text."""
import hashlib
import json
import mmap
import os
from pathlib import Path
import re
import stat
import subprocess

UNITS = ('nexus-gateway.service', 'nexus-workspace-agent.service', 'nexus-agent-orchestrator.service')
MODULES = ('server.py', 'run_jobs.py', 'approvals.py', 'approval_checkpoints.py', 'patch_dispatch.py',
           'patch_execution.py', 'command_approvals.py', 'command_dispatch.py', 'command_review.py', 'hermes_engine.py')
ENTRYPOINTS = ('server.py', 'nexus-agent-orchestrator.py', 'nexus-orchestrator.py',
               'nexus-agent-orchestrator', 'nexus-orchestrator')
PYTHON_FLAGS = {b'-u', b'-B', b'-E', b'-s', b'-S', b'-I', b'-O', b'-OO', b'-P', b'-q'}
MAGIC = b'\xff Go buildinf:'
MAX_BINARY = 256 << 20


def go_metadata(data):
    result = {}
    offset = data.find(MAGIC)
    if offset < 0 or offset + 32 > len(data) or not data[offset + 15] & 2:
        return result
    def text_at(cursor):
        size, shift = 0, 0
        for _ in range(10):
            if cursor >= len(data): raise ValueError('truncated build metadata')
            value = data[cursor]; cursor += 1
            size |= (value & 127) << shift
            if value < 128: break
            shift += 7
        else: raise ValueError('invalid metadata length')
        if size > 1 << 20 or cursor + size > len(data): raise ValueError('oversized build metadata')
        return bytes(data[cursor:cursor + size]), cursor + size
    try:
        version, cursor = text_at(offset + 32)
        module, _ = text_at(cursor)
    except ValueError:
        return result
    if re.fullmatch(rb'go[0-9][0-9a-zA-Z.+-]{0,63}', version): result['go_version'] = version.decode('ascii')
    for name, pattern in (('vcs_revision', rb'[0-9a-f]{40}'), ('vcs_modified', rb'true|false')):
        setting = b'vcs.revision' if name == 'vcs_revision' else b'vcs.modified'
        match = re.search(rb'(?:^|\n)build\t' + re.escape(setting) + b'=(' + pattern + rb')(?:\n|$)', module)
        if match: result[name] = match.group(1).decode('ascii')
    return result


def digest_stream(source, limit):
    before = os.fstat(source.fileno())
    if not 0 <= before.st_size <= limit: raise ValueError('file exceeds probe limit')
    digest = hashlib.sha256()
    remaining = limit + 1
    while remaining:
        data = source.read(min(65536, remaining))
        if not data: break
        digest.update(data); remaining -= len(data)
    after = os.fstat(source.fileno())
    if not remaining or (before.st_ino, before.st_size, before.st_mtime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns):
        raise ValueError('file changed or exceeds probe limit')
    return digest.hexdigest()


def digest_file(path, limit):
    # A deployed source path may be replaced while inspected. Refuse symlinks
    # and special files without blocking on a FIFO before inspecting its type.
    descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, 'rb') as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ValueError('source is not a regular file')
        return digest_stream(source, limit)


def entrypoint_from_args(commandline):
    if len(commandline) > 32768: raise ValueError('argv exceeds probe bound')
    args = commandline.rstrip(b'\0').split(b'\0')
    if not re.fullmatch(rb'python(?:[0-9]+(?:\.[0-9]+)*)?', args[0].rsplit(b'/', 1)[-1]):
        raise StopIteration
    for arg in args[1:]:
        if arg in PYTHON_FLAGS: continue
        # Never scan later operands: a token-file argument is not entry code.
        if not arg or arg.startswith(b'-'): raise StopIteration
        candidate = Path(os.fsdecode(arg))
        if candidate.suffix == '.py' or candidate.name in ENTRYPOINTS:
            return candidate
        raise StopIteration
    raise StopIteration


def unit_property(unit, name):
    try:
        reply = subprocess.run(['systemctl', '--user', 'show', unit, '--property=' + name, '--value'],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3, check=True)
        return reply.stdout.decode('ascii', errors='replace').strip()
    except (OSError, subprocess.SubprocessError): return ''


def inspect_service(unit):
    state = unit_property(unit, 'ActiveState')
    result = {'unit': unit, 'active_state': state if state in ('active', 'inactive', 'failed', 'activating', 'deactivating') else 'not_reported'}
    pid = unit_property(unit, 'MainPID')
    if not pid.isdigit() or int(pid) <= 0:
        result['runtime_provenance'] = 'no_running_pid'
        return result
    result['pid'] = int(pid)
    executable = Path('/proc') / pid / 'exe'
    try:
        with executable.open('rb') as source:
            result['executable_sha256'] = digest_stream(source, MAX_BINARY)
            with mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ) as data:
                if len(data) <= MAX_BINARY: result.update(go_metadata(data))
        result['runtime_provenance'] = 'executable_digest_only'
    except (OSError, ValueError): result['runtime_provenance'] = 'executable_not_accessible'
    if unit == 'nexus-agent-orchestrator.service':
        try:
            # Parse only Python's actual script operand; no argv is emitted.
            with (Path('/proc') / pid / 'cmdline').open('rb') as source:
                commandline = source.read(32769)
            entry = entrypoint_from_args(commandline)
            if not entry.is_absolute(): entry = (Path('/proc') / pid / 'cwd').resolve() / entry
            result['python_disk_entrypoint_sha256'] = digest_file(entry, 2 << 20)
            hashes = {}
            for name in MODULES:
                path = entry.parent / name
                if path.is_file() and not path.is_symlink(): hashes[name] = digest_file(path, 2 << 20)
            result['python_disk_module_sha256'] = hashes
            result['python_loaded_modules'] = 'not_attested; disk hashes do not prove loaded bytecode'
        except StopIteration: result['python_disk_modules'] = 'script_entrypoint_not_safely_identified'
        except (OSError, ValueError): result['python_disk_modules'] = 'not_accessible_or_exceeds_bound'
    if unit_property(unit, 'MainPID') != pid:
        return {'unit': unit, 'runtime_provenance': 'process_changed_during_probe'}
    return result


def main():
    print(json.dumps({'probe': 'read_only_nexus_service_provenance_v1',
                      'services': [inspect_service(unit) for unit in UNITS]}, indent=2, sort_keys=True))


if __name__ == '__main__': main()
