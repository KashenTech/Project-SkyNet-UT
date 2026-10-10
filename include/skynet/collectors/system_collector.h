#pragma once
// SkyNet — System Collector
// Monitors system errors: crashes, segfaults, OOM kills, permission denials, log tampering.

#include "collector.h"
#include "../utils/file_watcher.h"
#include "../utils/uuid.h"
#include <map>

namespace skynet {

class SystemCollector : public Collector {
public:
    std::string name() const override { return "system"; }
    bool enabled() const override { return enabled_; }
    bool init(const Config& config) override;
    void collect(const EventCallback& emit) override;
    CollectorStatus status() const override;

private:
    bool enabled_ = true;
    CollectorStatus status_{"system"};
    std::unique_ptr<FileWatcher> syslog_watcher_;

    // Track log file sizes for tamper detection
    struct LogFileState {
        off_t last_size;
        ino_t last_inode;
    };
    std::map<std::string, LogFileState> log_baselines_;
    std::vector<std::string> monitored_logs_;

    void parse_syslog_line(const std::string& line, const EventCallback& emit);
    void check_log_tampering(const EventCallback& emit);
    void check_dmesg(const EventCallback& emit);
};

} // namespace skynet
