// Nexus's opt-in model control surface. The console continues to run llama-server
// on port 8081 and uses its established restart flow for a model switch.
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "stats.hpp"
#include <array>
#include <atomic>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace ps5lm {
class NexusControl {
  public:
    NexusControl() = default;
    ~NexusControl();
    NexusControl(const NexusControl &) = delete;
    NexusControl & operator=(const NexusControl &) = delete;

    // Disabled unless a strong operator-provisioned token exists. Loopback is
    // the default; the LAN opt-in marker enables access from a private gateway.
    bool start(const std::string & token_file, bool allow_lan, unsigned short port = 8082);
    void stop();
    unsigned short port() const;
    void publish(const Live & live, const std::vector<ModelRow> & models);
    std::optional<std::string> take_request(); // "none" to unload, model path to load
    void mark_restart_failed(); // LoadExec returned instead of replacing the process

    static std::string model_id(const std::string & path);
  private:
    void serve();
    void handle(int fd);
    mutable std::mutex mutex_;
    std::array<unsigned char, 32> token_hash_{};
    Live live_;
    std::vector<ModelRow> models_;
    std::optional<std::string> pending_;
    bool switching_ = false;
    bool restart_failed_ = false;
    std::atomic<bool> stopped_{true};
    int listener_ = -1;
    unsigned short port_ = 0;
    std::thread thread_;
};
} // namespace ps5lm
