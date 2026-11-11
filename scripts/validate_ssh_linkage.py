"""Reject SSH binaries with missing Atomic metadata or the old NIOTS connector.

The optimized NIO code allocates ManagedAtomic<Bool> through runtime metadata
lookup. Archive extraction can omit AtomicBool.o when all ordinary uses inline.
The resulting nil metadata was observed in Nexus build 26's crash registers.
"""
from pathlib import Path
import plistlib
import struct
import sys
import zipfile

REQUIRED = frozenset({
    '_$sSb7Atomics11AtomicValueAAMc',
    '_$sSb7Atomics11AtomicValueAAWP',
    '_$s7Atomics13ManagedAtomicCMn',
})
POSIX_CONNECTOR_MARKER = b'NIOPosix15ClientBootstrapC'
FORBIDDEN_CONNECTOR_MARKERS = (b'NIOTSConnectionBootstrap', b'NIOTransportServices')


def defined_symbols(binary: bytes) -> set[str]:
    if len(binary) < 32:
        raise ValueError('Truncated Mach-O header.')
    magic, cpu, _, _, count, command_bytes, _, _ = struct.unpack_from('<8I', binary)
    if magic != 0xFEEDFACF or cpu != 0x0100000C:
        raise ValueError('Expected a thin arm64 Mach-O executable.')
    command_end = 32 + command_bytes
    if command_end > len(binary) or count > command_bytes // 8:
        raise ValueError('Invalid Mach-O load-command bounds.')
    offset = 32
    symtab = None
    for _ in range(count):
        if offset + 8 > command_end:
            raise ValueError('Truncated Mach-O load command.')
        command, size = struct.unpack_from('<2I', binary, offset)
        if size < 8 or offset + size > command_end:
            raise ValueError('Invalid Mach-O load-command size.')
        if command == 2:
            if size != 24 or symtab is not None:
                raise ValueError('Invalid Mach-O symbol table.')
            symtab = struct.unpack_from('<4I', binary, offset + 8)
        offset += size
    if symtab is None:
        raise ValueError('SSH linkage gate requires the xtool symbol table before stripping.')
    symoff, nsyms, stroff, strsize = symtab
    if symoff + nsyms * 16 > len(binary) or stroff + strsize > len(binary):
        raise ValueError('Invalid Mach-O symbol-table bounds.')
    strings = binary[stroff:stroff + strsize]
    result = set()
    for index in range(nsyms):
        name_index, kind, _, _, _ = struct.unpack_from('<IBBHQ', binary, symoff + index * 16)
        if name_index >= len(strings):
            raise ValueError('Invalid Mach-O symbol-name offset.')
        if kind & 0xE0 or not kind & 0x0E:  # Ignore debug records and undefined imports.
            continue
        end = strings.find(b'\0', name_index)
        if end < 0:
            raise ValueError('Unterminated Mach-O symbol name.')
        result.add(strings[name_index:end].decode('utf-8', errors='replace'))
    return result


def validate(binary: bytes) -> None:
    for marker in FORBIDDEN_CONNECTOR_MARKERS:
        if marker in binary:
            raise ValueError('The app links the retired Network.framework SSH connector; rebuild with Citadel POSIX ClientBootstrap.')
    if POSIX_CONNECTOR_MARKER not in binary:
        raise ValueError('The app does not contain the expected NIO POSIX SSH connector.')
    missing = REQUIRED - defined_symbols(binary)
    if missing:
        raise ValueError('Missing SSH runtime metadata: ' + ', '.join(sorted(missing)) +
                         '. Rebuild the xtool app with -all_load; do not publish this executable.')


def load_executable(path: Path) -> bytes:
    if path.is_dir():
        info = plistlib.loads((path / 'Info.plist').read_bytes())
        return (path / info['CFBundleExecutable']).read_bytes()
    if path.suffix == '.ipa':
        with zipfile.ZipFile(path) as archive:
            root = 'Payload/Nexus.app/'
            info = plistlib.loads(archive.read(root + 'Info.plist'))
            return archive.read(root + info['CFBundleExecutable'])
    return path.read_bytes()


if __name__ == '__main__':
    try:
        validate(load_executable(Path(sys.argv[1])))
        print('Verified SSH runtime linkage: POSIX ClientBootstrap is present, NIOTS is absent, and ManagedAtomic<Bool> metadata is present.')
    except (OSError, ValueError, KeyError, zipfile.BadZipFile) as error:
        raise SystemExit(f'SSH linkage validation failed: {error}')
