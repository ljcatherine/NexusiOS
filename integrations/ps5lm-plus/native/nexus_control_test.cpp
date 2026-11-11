// Run on Linux host: c++ -std=c++20 -pthread ...
// SPDX-License-Identifier: GPL-3.0-or-later
#include "nexus_control.hpp"
#include "model_plan.hpp"
extern "C" {
#include "hash/sha256/sha256.h"
}
#include <arpa/inet.h>
#include <cassert>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <limits>
#include <locale>
#include <netinet/in.h>
#include <string>
#include <sys/stat.h>
#include <sys/socket.h>
#include <unistd.h>
#include <vector>

// Host linker seam: exercise a different effective UID without privileges,
// filesystem ownership changes or changing the production security check.
static bool different_euid = false;
static bool sanitized_stat = false;
static uid_t sanitized_euid = 1;
static uid_t sanitized_file_uid = 0;
static nlink_t sanitized_links = 0;
static bool fail_credential_read = false;
extern "C" uid_t __real_geteuid();
extern "C" uid_t __wrap_geteuid() {
    if (sanitized_stat) return sanitized_euid;
    const uid_t actual = __real_geteuid();
    return different_euid ? actual ^ 1u : actual;
}
extern "C" int __real_fstat(int, struct stat *);
extern "C" int __wrap_fstat(int fd, struct stat * st) {
    const int result = __real_fstat(fd, st);
    if (result == 0 && sanitized_stat) { st->st_uid = sanitized_file_uid; st->st_nlink = sanitized_links; }
    return result;
}
extern "C" ssize_t __real_read(int, void *, size_t);
extern "C" ssize_t __wrap_read(int fd, void * data, size_t size) {
    if (fail_credential_read) { errno = EIO; return -1; }
    return __real_read(fd, data, size);
}

static std::string request(unsigned short port, const std::string & request) {
    const int fd = socket(AF_INET, SOCK_STREAM, 0);
    assert(fd >= 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    assert(connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) == 0);
    assert(send(fd, request.data(), request.size(), 0) == (ssize_t)request.size());
    std::string response;
    char buffer[4096];
    for (ssize_t count; (count = recv(fd, buffer, sizeof(buffer), 0)) > 0; ) {
        response.append(buffer, (size_t)count);
    }
    close(fd);
    return response;
}
static std::string query(unsigned short port, const std::string & method, const std::string & path,
                         const std::string & authorization) {
    return request(port, method + " " + path + " HTTP/1.1\r\nHost: localhost\r\n" +
        (authorization.empty() ? "" : "Authorization: Bearer " + authorization + "\r\n") +
        "Content-Length: 0\r\nConnection: close\r\n\r\n");
}
struct comma_decimal : std::numpunct<char> {
    char do_decimal_point() const override { return ','; }
};

static std::string little_endian(uint64_t value, size_t count) {
    std::string bytes;
    for (size_t i = 0; i < count; ++i) bytes.push_back(static_cast<char>((value >> (8 * i)) & 255));
    return bytes;
}
static std::string gguf_string(const std::string & text) {
    return little_endian(text.size(), 8) + text;
}
static std::string gguf_header(const std::vector<std::pair<uint32_t, std::string>> & types) {
    std::string data = "GGUF" + little_endian(3, 4) + little_endian(0, 8) + little_endian(2 + types.size(), 8);
    data += gguf_string("general.architecture") + little_endian(8, 4) + gguf_string("qwen35");
    data += gguf_string("qwen35.block_count") + little_endian(4, 4) + little_endian(32, 4);
    for (const auto & entry : types) {
        data += gguf_string("general.file_type") + little_endian(entry.first, 4) + entry.second;
    }
    return data;
}

static void test_gguf_metadata() {
    for (const auto & types : std::vector<std::vector<std::pair<uint32_t, std::string>>>{
            {}, {{8, gguf_string("Q6_K")}}, {{10, little_endian(18, 8)}},
            {{6, little_endian(0x7fc00000, 4)}}, // NaN must be skipped without integer conversion.
            {{4, little_endian(18, 4)}, {4, little_endian(2, 4)}},
            {{4, little_endian(1024, 4)}}}) {
        const auto info = ps5lm::read_model_header("misleading-Q6_K.gguf", gguf_header(types), 123456);
        assert(info.ok && !info.file_type.has_value());
    }
    for (const uint32_t type : {0u, 18u, 999u}) {
        const auto info = ps5lm::read_model_header("misleading-Q4_K_M.gguf",
            gguf_header({{4, little_endian(type, 4)}}), 123456);
        assert(info.ok && info.file_type == type && info.file_bytes == 123456);
    }
    std::string truncated = gguf_header({{4, little_endian(18, 4)}});
    truncated.pop_back();
    const auto bad = ps5lm::read_model_header("Q6_K.gguf", truncated, 123456);
    assert(!bad.ok && !bad.file_type.has_value());
    const auto array = ps5lm::read_model_header("Q6_K.gguf",
        gguf_header({{9, little_endian(6, 4) + little_endian(1, 8) + little_endian(0x7fc00000, 4)}}), 123456);
    assert(!array.ok && !array.file_type.has_value());
#if defined(__linux__)
    int descriptors[2];
    assert(pipe(descriptors) == 0);
    const auto header = gguf_header({{4, little_endian(18, 4)}});
    assert(write(descriptors[1], header.data(), header.size()) == static_cast<ssize_t>(header.size()));
    close(descriptors[1]);
    const auto nonseekable = ps5lm::read_model_info("/proc/self/fd/" + std::to_string(descriptors[0]));
    close(descriptors[0]);
    assert(!nonseekable.ok && nonseekable.file_bytes == 0 && !nonseekable.file_type.has_value());
#endif
}

int main() {
    test_gguf_metadata();
    const std::string token = "ABCDEF0123456789ABCDEF0123456789";
    unsigned char digest[32];
    sha256_hash(digest, reinterpret_cast<const unsigned char *>(token.data()), token.size());
    std::string stored = "sha256:";
    const char * hex = "0123456789abcdef";
    for (const unsigned char byte : digest) {
        stored += hex[byte >> 4];
        stored += hex[byte & 0x0f];
    }
    char directory_pattern[] = "/tmp/ps5lm-nexus-control-XXXXXX";
    const char * directory = mkdtemp(directory_pattern);
    assert(directory != nullptr);
    const std::string filename = std::string(directory) + "/token";
    FILE * diagnostics = tmpfile();
    assert(diagnostics != nullptr);
    fflush(stdout);
    const int original_stdout = dup(STDOUT_FILENO);
    assert(original_stdout >= 0 && dup2(fileno(diagnostics), STDOUT_FILENO) >= 0);
    ps5lm::NexusControl api;
    assert(!api.start(filename, false, 0)); // fail closed without token
    const std::string fifo_name = filename + ".fifo";
    assert(mkfifo(fifo_name.c_str(), 0600) == 0);
    alarm(3); // A blocking open must fail this regression, not hang the suite.
    assert(!api.start(fifo_name, false, 0));
    alarm(0);
    unlink(fifo_name.c_str());
    { std::ofstream out(filename); out << stored << "\n"; }
    chmod(filename.c_str(), 0644);
    assert(!api.start(filename, false, 0)); // reject group/world-readable token hash
    chmod(filename.c_str(), 0600);
    { std::ofstream out(filename); out << "short\n"; }
    chmod(filename.c_str(), 0600);
    assert(!api.start(filename, false, 0)); // reject malformed stored hash
    { std::ofstream out(filename); out << "sha256:" << std::string(64, 'z') << "\n"; }
    assert(!api.start(filename, false, 0));
    { std::ofstream out(filename); out << stored << "\n"; }
    chmod(filename.c_str(), 0600);
    const std::string symlink_name = filename + ".link";
    assert(symlink(filename.c_str(), symlink_name.c_str()) == 0);
    assert(!api.start(symlink_name, false, 0)); // reject symlinked credential files
    unlink(symlink_name.c_str());
    different_euid = true;
    assert(!api.start(filename, false, 0)); // owned file must match effective process UID
    different_euid = false;
    fail_credential_read = true;
    assert(!api.start(filename, false, 0));
    fail_credential_read = false;
#if defined(NEXUS_CONTROL_REQUIRE_PROVISIONING_PIN)
    // Even a correctly owned private file cannot substitute another digest.
    { std::ofstream out(filename); out << "sha256:" << std::string(64, '0') << "\n"; }
    assert(!api.start(filename, false, 0));
    for (const auto & malformed : {stored, stored + "\n\n", stored + "\nextra", stored + std::string(200, 'x')}) {
        { std::ofstream out(filename); out << malformed; }
        assert(!api.start(filename, false, 0));
    }
    { std::ofstream out(filename); out << stored << "\n"; }
    for (const auto mode : {0644, 04600, 0400}) {
        chmod(filename.c_str(), mode);
        assert(!api.start(filename, false, 0));
    }
    chmod(filename.c_str(), 0600);
#endif
    sanitized_stat = true;
#if defined(NEXUS_CONTROL_REQUIRE_PROVISIONING_PIN)
    sanitized_euid = 2;
    assert(!api.start(filename, false, 0));
    sanitized_euid = 1;
    sanitized_file_uid = 2;
    assert(!api.start(filename, false, 0));
    sanitized_file_uid = 0;
    sanitized_links = 1;
    assert(!api.start(filename, false, 0));
    sanitized_links = 0;
    for (const auto mode : {0644, 04600, 0400}) {
        chmod(filename.c_str(), mode);
        assert(!api.start(filename, false, 0));
    }
    chmod(filename.c_str(), 0600);
    assert(api.start(filename, false, 0));
    const auto pinned_port = api.port();
    assert(query(pinned_port, "GET", "/v1/nexus/status", "").find("401 Unauthorized") != std::string::npos);
    assert(query(pinned_port, "GET", "/v1/nexus/status", "wrong-token").find("401 Unauthorized") != std::string::npos);
    assert(query(pinned_port, "GET", "/v1/nexus/status", stored.substr(7)).find("401 Unauthorized") != std::string::npos);
    assert(query(pinned_port, "GET", "/v1/nexus/status", token).find("200 OK") != std::string::npos);
    api.stop();
    { std::ofstream out(filename); out << "sha256:" << std::string(64, '0') << "\n"; }
    assert(!api.start(filename, false, 0));
    { std::ofstream out(filename); out << stored << "\n"; }
#else
    assert(!api.start(filename, false, 0)); // no pin never permits concealed ownership
#endif
    sanitized_stat = false;
    assert(api.start(filename, false, 0));
    fflush(stdout);
    assert(dup2(original_stdout, STDOUT_FILENO) >= 0);
    close(original_stdout);
    rewind(diagnostics);
    std::string startup_log;
    char log_buffer[512];
    for (size_t count; (count = fread(log_buffer, 1, sizeof(log_buffer), diagnostics)) > 0; )
        startup_log.append(log_buffer, count);
    fclose(diagnostics);
    for (const char * stage : {"credential_open", "credential_type", "credential_permissions", "credential_format", "credential_owner"})
        assert(startup_log.find(std::string("stage=") + stage + " errno=") != std::string::npos);
    assert(startup_log.find("file_uid=") != std::string::npos);
    assert(startup_log.find("process_euid=") != std::string::npos);
    assert(startup_log.find("identity dev=") != std::string::npos);
    assert(startup_log.find("path_identity result=0 errno=0 dev=") != std::string::npos);
    assert(startup_log.find("stat_word offset=12 value=") != std::string::npos);
    assert(startup_log.find(token) == std::string::npos);
    assert(startup_log.find(stored) == std::string::npos);
    assert(startup_log.find(filename) == std::string::npos);
    auto port = api.port(); assert(port != 0);
    std::locale::global(std::locale(std::locale::classic(), new comma_decimal));
    ps5lm::Live live;
    live.state = ps5lm::ServerState::ready;
    live.ctx = 32768;
    live.ctx_used = 2113;
    live.gen_tps = 18.5f;
    live.prompt_tps = 132.0f;
    live.pool_gib = 12.0;
    live.free_gib = 1.9;
    live.model_gib = 8.2;
    live.kv_gib = 1.1;
    live.load_progress = -1.0f;
    live.model_file = "/data/PS5LM/models/active.gguf";
    live.model_label = "Qwen \"active\"";
    ps5lm::ModelRow active;
    active.file = live.model_file;
    active.label = live.model_label;
    active.fits = true;
    active.current = true;
    const std::string model_path = std::string(directory) + "/misleading-Q4_K_M.gguf";
    const std::string model_data = gguf_header({{4, little_endian(18, 4)}}) + std::string(256, '\0');
    { std::ofstream out(model_path, std::ios::binary); out.write(model_data.data(), model_data.size()); }
    const auto model_info = ps5lm::read_model_info(model_path);
    assert(model_info.ok && model_info.file_bytes == model_data.size() && model_info.file_type == 18);
    active.arch = model_info.arch;
    active.file = model_path;
    live.model_file = model_path;
    active.file_bytes = model_info.file_bytes;
    active.file_type = model_info.file_type;
    unlink(model_path.c_str());
    ps5lm::ModelRow other;
    other.file = "/mnt/usb0/PS5LM/models/other.gguf";
    other.label = "other";
    other.fits = true;
    api.publish(live, {active, other});
    assert(query(port, "GET", "/v1/nexus/models", "").find("401 Unauthorized") != std::string::npos);
    assert(query(port, "GET", "/v1/nexus/models", "wrong").find("401 Unauthorized") != std::string::npos);
    assert(query(port, "GET", "/v1/nexus/models", token + "\xc3\xa9").find("401 Unauthorized") != std::string::npos);
    const auto duplicate_auth = request(port,
        "GET /v1/nexus/status HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + token +
        "\r\nAuthorization: Bearer " + token + "\r\nContent-Length: 0\r\n\r\n");
    assert(duplicate_auth.find("401 Unauthorized") != std::string::npos);
    const auto body_request = request(port,
        "POST /v1/nexus/models/unload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + token +
        "\r\nContent-Length: 1\r\n\r\nx");
    assert(body_request.find("400 Bad Request") != std::string::npos);
    assert(!api.take_request());
    const auto chunked_request = request(port,
        "POST /v1/nexus/models/unload HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + token +
        "\r\nTransfer-Encoding: chunked\r\n\r\n");
    assert(chunked_request.find("400 Bad Request") != std::string::npos);
    assert(!api.take_request());
    const auto models = query(port, "GET", "/v1/nexus/models", token);
    assert(models.find("200 OK") != std::string::npos);
    assert(models.find("\"architecture\":\"qwen35\"") != std::string::npos);
    assert(models.find("\"file_size_bytes\":" + std::to_string(model_data.size())) != std::string::npos);
    assert(models.find("\"quantization_type\":18") != std::string::npos);
    assert(models.find("\"quantization_type\":null") != std::string::npos);
    assert(models.find("\"file_size_bytes\":null") != std::string::npos);
    assert(models.find("/data/PS5LM") == std::string::npos);
    assert(models.find(directory) == std::string::npos);
    auto unknown = other;
    unknown.file_type = 999;
    unknown.file_bytes = std::numeric_limits<uint64_t>::max();
    unknown.arch = "bad\narchitecture";
    api.publish(live, {unknown});
    const auto future = query(port, "GET", "/v1/nexus/models", token);
    assert(future.find("\"quantization_type\":999") != std::string::npos);
    assert(future.find("\"file_size_bytes\":null") != std::string::npos);
    assert(future.find("\"architecture\":null") != std::string::npos);
    unknown.file_type = 1024;
    api.publish(live, {unknown});
    assert(query(port, "GET", "/v1/nexus/models", token).find("\"quantization_type\":null") != std::string::npos);
    api.publish(live, {active, other});
    assert(models.find("Qwen \\\"active\\\"") != std::string::npos);
    const auto status = query(port, "GET", "/v1/nexus/status", token);
    assert(status.find("\"ready\":true") != std::string::npos);
    assert(status.find("\"context_size\":32768") != std::string::npos);
    assert(status.find("\"context_used\":2113") != std::string::npos);
    assert(status.find("\"generation_tps\":18.5") != std::string::npos);
    assert(status.find("\"prompt_tps\":132") != std::string::npos);
    assert(status.find("\"memory_pool_gib\":12") != std::string::npos);
    assert(status.find("\"memory_free_gib\":1.9") != std::string::npos);
    assert(status.find("\"model_gib\":8.2") != std::string::npos);
    assert(status.find("\"kv_cache_gib\":1.1") != std::string::npos);
    assert(status.find("\"load_progress\":null") != std::string::npos);
    live.gen_tps = std::numeric_limits<float>::quiet_NaN();
    live.prompt_tps = std::numeric_limits<float>::infinity();
    live.free_gib = -1.0;
    api.publish(live, {active, other});
    const auto unavailable = query(port, "GET", "/v1/nexus/status", token);
    assert(unavailable.find("\"generation_tps\":null") != std::string::npos);
    assert(unavailable.find("\"prompt_tps\":null") != std::string::npos);
    assert(unavailable.find("\"memory_free_gib\":null") != std::string::npos);
    assert(query(port, "POST", "/v1/nexus/models/not-valid/load", token).find("404 Not Found") != std::string::npos);
    const auto id = ps5lm::NexusControl::model_id(other.file);
    live.state = ps5lm::ServerState::generating;
    api.publish(live, {active, other});
    assert(query(port, "POST", "/v1/nexus/models/"+id+"/load", token).find("409 Conflict") != std::string::npos);
    assert(!api.take_request());
    live.state = ps5lm::ServerState::ready;
    api.publish(live, {active, other});
    assert(query(port, "POST", "/v1/nexus/models/"+id+"/load", token).find("202 Accepted") != std::string::npos);
    assert(query(port, "POST", "/v1/nexus/models/unload", token).find("409 Conflict") != std::string::npos);
    const auto selected = api.take_request();
    assert(selected && *selected == other.file);
    assert(!api.take_request());
    assert(query(port, "GET", "/v1/nexus/status", token).find("\"state\":\"switching\"") != std::string::npos);
    api.mark_restart_failed();
    assert(query(port, "GET", "/v1/nexus/status", token).find("\"state\":\"restart_failed\"") != std::string::npos);
    assert(query(port, "POST", "/v1/nexus/models/"+id+"/load", token).find("202 Accepted") != std::string::npos);
    api.stop();
    unlink(filename.c_str());
    assert(rmdir(directory) == 0);
    puts("Nexus native PS5 control tests passed");
}
