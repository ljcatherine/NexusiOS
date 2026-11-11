// One-shot provisioning repair, not a network service or application endpoint.
// SPDX-License-Identifier: GPL-3.0-or-later
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int digest_matches(int fd, const char *expected) {
    char contents[73];
    return lseek(fd, 0, SEEK_SET) == 0 && read(fd, contents, sizeof(contents)) == 72 &&
        contents[71] == '\n' && memcmp(contents, expected, 71) == 0;
}

// Keep permissions/content/inode unchanged. Refuse unexpected ownership,
// linked files and digest drift before attempting a descriptor-based chown.
static int repair_control_owner(const char *directory, const char *expected,
                                uid_t app_uid) {
    int result = 1;
    struct stat before, after, log_info;
    int dir = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0) return 1;
    int log = openat(dir, "app.log", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    int token = openat(dir, "nexus-control.token", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (log < 0 || token < 0) goto done;
    if (fstat(log, &log_info) || !S_ISREG(log_info.st_mode) || log_info.st_uid != app_uid)
        goto done;
    if (fstat(token, &before) || !S_ISREG(before.st_mode) || before.st_nlink != 1 ||
        (before.st_mode & 07777) != 0600 || before.st_size != 72 ||
        (before.st_uid != 0 && before.st_uid != app_uid)) goto done;
    if (strlen(expected) != 71 || strncmp(expected, "sha256:", 7)) goto done;
    for (int i = 7; i < 71; ++i)
        if (!((expected[i] >= '0' && expected[i] <= '9') ||
              (expected[i] >= 'a' && expected[i] <= 'f'))) goto done;
    if (!digest_matches(token, expected)) goto done;
    if (before.st_uid != app_uid && fchown(token, app_uid, (gid_t)-1)) goto done;
    if (fstat(token, &after) || after.st_uid != app_uid ||
        after.st_gid != before.st_gid || after.st_ino != before.st_ino ||
        (after.st_mode & 07777) != 0600 || after.st_size != 72 ||
        !digest_matches(token, expected)) goto done;
    result = 0;
done:
    if (token >= 0) close(token);
    if (log >= 0) close(log);
    close(dir);
    return result;
}

#ifndef NEXUS_OWNER_REPAIR_HOST_TEST
#ifndef NEXUS_EXPECTED_CONTROL_DIGEST
#error Supply the independently verified digest through a private build header.
#endif
int main(void) {
    int result = repair_control_owner("/data/PS5LM", NEXUS_EXPECTED_CONTROL_DIGEST, 1);
    puts(result ? "Nexus controller ownership repair refused/failed" :
                  "Nexus controller ownership verified; reopen test title");
    return result;
}
#endif
