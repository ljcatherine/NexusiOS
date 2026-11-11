import os
from pathlib import Path

directory = Path(os.environ['FIXTURE_DIR'])
username = os.environ['NEXUS_TEST_USER']
pam_option = '' if username == 'root' else 'UsePAM no\n'
(directory / 'fakebin').mkdir(mode=0o700)
(directory / 'fakebin/systemctl').write_text(f'''#!/bin/sh
case "$1" in
  --no-legend)
    printf 'nexus-test.service loaded active running Disposable Nexus fixture\\n'
    printf 'inactive-test.service loaded inactive dead Disposable inactive fixture\\n'
    ;;
  start|stop|restart)
    printf '%s %s\\n' "$1" "$2" >> '{directory}/sftp-root/systemctl-actions.log'
    printf 'fixture %s %s\\n' "$1" "$2"
    ;;
  *) exit 2 ;;
esac
''')
(directory / 'fakebin/journalctl').write_text('''#!/bin/sh
printf 'fixture journal entry\\n'
''')
(directory / 'fakebin/ps').write_text('''#!/bin/sh
printf '123 fixture 12.5 3.0 S nexus process fixture\\n'
''')
(directory / 'fakebin/sudo').write_text('''#!/bin/sh
[ "$1" = "-n" ] || exit 64
shift
exec "$@"
''')
(directory / 'fakebin/nixos-version').write_text('''#!/bin/sh
printf '26.05-fixture\\n'
''')
(directory / 'fakebin/nixos-rebuild').write_text(f'''#!/bin/sh
printf 'nixos-rebuild %s\\n' "$*" >> '{directory}/sftp-root/nixos-rebuild-actions.log'
if [ -f '{directory}/sftp-root/fail-dry-build' ] && [ "$1" = "dry-build" ]; then
  printf 'fixture dry-build failed\\n'
  exit 23
fi
printf 'fixture nixos-rebuild %s\\n' "$*"
''')
for executable in (directory / 'fakebin').iterdir():
    executable.chmod(0o700)
(directory / 'sshd_config').write_text(
    f'Port 22222\nListenAddress 127.0.0.1\nHostKey {directory}/host\n'
    f'PidFile {directory}/sshd.pid\nAuthorizedKeysFile {directory}/client.pub\n'
    f'StrictModes no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n'
    f'Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com\n'
    f'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com\n'
    f'PermitRootLogin yes\n{pam_option}AllowUsers {username}\n'
    f'Subsystem sftp internal-sftp\n'
    f'SetEnv PATH={directory}/fakebin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n'
    f'LogLevel INFO\n')
