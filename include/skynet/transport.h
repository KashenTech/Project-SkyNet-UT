#pragma once
// SkyNet — Transport (JSON File Writer)
// Writes batched events and alerts to JSON files for backend consumption.

#include "types.h"
#include "config.h"
#include <vector>
#include <string>
#include <mutex>
#include <atomic>

namespace skynet {

class Transport {
public:
    void init(const Config& config);

    /// Write a batch of events to the output file.
    /// Returns true on success.
    bool send_events(const std::vector<Event>& events);

    /// Write alerts to the alerts file.
    bool send_alerts(const std::vector<Alert>& alerts);

    /// Write host metadata.
    bool send_host_info(const HostInfo& info);

    /// Transport health.
    bool is_healthy() const { return healthy_; }
    uint64_t total_sent() const { return total_sent_; }
    uint64_t total_failed() const { return total_failed_; }

private:
    std::string output_file_;
    std::string alerts_file_;
    std::mutex write_mtx_;

    std::atomic<bool>     healthy_{true};
    std::atomic<uint64_t> total_sent_{0};
    std::atomic<uint64_t> total_failed_{0};

    bool append_json_lines(const std::string& path, const std::vector<nlohmann::json>& lines);
    bool write_json_file(const std::string& path, const nlohmann::json& data);
    void ensure_directory(const std::string& path);
};

} // namespace skynet
