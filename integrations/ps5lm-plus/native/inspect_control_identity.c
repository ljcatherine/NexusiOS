// One-shot metadata inspection. Never reads or changes credential contents.
// SPDX-License-Identifier: GPL-3.0-or-later
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void print_metadata(FILE *out, const struct stat *value) {
    const struct stat st = *value;
    fprintf(out, "{\"dev\":%llu,\"ino\":%llu,\"mode\":%u,\"uid\":%llu,\"gid\":%llu,\"size\":%lld,\"stat_bytes\":%zu,\"words\":[",
            (unsigned long long)st.st_dev, (unsigned long long)st.st_ino,
            (unsigned)st.st_mode, (unsigned long long)st.st_uid,
            (unsigned long long)st.st_gid, (long long)st.st_size, sizeof(st));
    const unsigned char * metadata = (const unsigned char *)&st;
    for (size_t offset = 0; offset < 32; offset += 4) {
        uint32_t word = 0;
        memcpy(&word, metadata + offset, sizeof(word));
        fprintf(out, "%s%u", offset ? "," : "", word);
    }
    fputs("]}", out);
}

int main(void) {
    struct stat token, log_path, log_fd;
    memset(&token, 0, sizeof(token));
    memset(&log_path, 0, sizeof(log_path));
    memset(&log_fd, 0, sizeof(log_fd));
    if (lstat("/data/PS5LM/nexus-control.token", &token) || !S_ISREG(token.st_mode)) return 1;
    if (lstat("/data/PS5LM/app.log", &log_path) || !S_ISREG(log_path.st_mode)) return 1;
    int log = open("/data/PS5LM/app.log", O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (log < 0) return 1;
    int status = fstat(log, &log_fd);
    close(log);
    if (status) return 1;
    int fd = open("/data/PS5LM/.nexus-control-identity-pair-20261106.json",
                  O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return 1;
    FILE * out = fdopen(fd, "w");
    if (!out) { close(fd); return 1; }
    fputs("{\"token_lstat\":", out);
    print_metadata(out, &token);
    fputs(",\"log_lstat\":", out);
    print_metadata(out, &log_path);
    fputs(",\"log_fstat\":", out);
    print_metadata(out, &log_fd);
    fputs("}\n", out);
    int failed = ferror(out);
    if (fclose(out)) failed = 1;
    return failed ? 1 : 0;
}
