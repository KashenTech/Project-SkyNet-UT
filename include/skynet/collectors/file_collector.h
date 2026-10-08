#pragma once
// SkyNet — File Change Collector
// Monitors critical paths for file creation, modification, deletion.

#include "collector.h"
#include "../utils/uuid.h"
#include <map>

namespace skynet {

class FileCollector : public Collector {
public:
    std::string name() const override { return "file"; }
    bool enabled() const override { return enabled_; }
    bool init(const Config& config) override;
    void collect(const EventCallback& emit) override;
    CollectorStatus status() const override;

private:
    bool enabled_ = true;
    CollectorStatus status_{"file"};
    std::vector<std::string> watch_paths_;

    // Baseline: path -> {mtime, size, inode}
    struct FileState {
        time_t mtime;
        off_t  size;
        ino_t  inode;
    };
    std::map<std::string, FileState> baseline_;
    bool baseline_initialized_ = false;

    void scan_directory(const std::string& dir, std::map<std::string, FileState>& out);
    std::string compute_file_hash(const std::string& path);
};

} // namespace skynet
