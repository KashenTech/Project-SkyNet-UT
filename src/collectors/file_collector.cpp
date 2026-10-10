// SkyNet — File Change Collector Implementation
// Monitors critical directories for file creation, modification, deletion.

#include "skynet/collectors/file_collector.h"
#include "skynet/utils/logger.h"
#include <dirent.h>
#include <sys/stat.h>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <functional>
#include <cstring>

namespace skynet {

static std::string now_utc() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&t, &tm);
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

bool FileCollector::init(const Config& config) {
    enabled_ = config.enable_file;
    if (!enabled_) return true;

    watch_paths_ = config.watch_paths;
    status_.enabled = true;
    status_.accessible = true;

    for (const auto& path : watch_paths_) {
        struct stat st{};
        if (stat(path.c_str(), &st) != 0) {
            LOG_WARN("file", "Watch path not accessible: " + path);
        }
    }
    return true;
}

void FileCollector::scan_directory(const std::string& dir, std::map<std::string, FileState>& out) {
    DIR* d = opendir(dir.c_str());
    if (!d) return;

    struct dirent* entry;
    while ((entry = readdir(d)) != nullptr) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        std::string full_path = dir + "/" + entry->d_name;
        struct stat st{};
        if (lstat(full_path.c_str(), &st) != 0) continue;

        if (S_ISREG(st.st_mode)) {
            out[full_path] = {st.st_mtime, st.st_size, st.st_ino};
        } else if (S_ISDIR(st.st_mode)) {
            // Recurse but limit depth to avoid runaway scanning
            // Only recurse 2 levels deep from watch root
            int depth = 0;
            for (char c : full_path) if (c == '/') depth++;
            if (depth < 8) {
                scan_directory(full_path, out);
            }
        }
    }
    closedir(d);
}

std::string FileCollector::compute_file_hash(const std::string& path) {
    // Simple djb2 hash of first 4KB for change detection (not crypto)
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";

    char buf[4096];
    f.read(buf, sizeof(buf));
    auto bytes_read = f.gcount();

    unsigned long hash = 5381;
    for (int i = 0; i < bytes_read; ++i) {
        hash = ((hash << 5) + hash) + static_cast<unsigned char>(buf[i]);
    }

    char hex[20];
    snprintf(hex, sizeof(hex), "%lx", hash);
    return std::string(hex);
}

void FileCollector::collect(const EventCallback& emit) {
    if (!enabled_) return;

    std::string ts = now_utc();
    std::map<std::string, FileState> current;

    for (const auto& path : watch_paths_) {
        scan_directory(path, current);
    }

    if (!baseline_initialized_) {
        baseline_ = current;
        baseline_initialized_ = true;
        status_.last_collect = ts;
        LOG_INFO("file", "File baseline established with " + std::to_string(current.size()) + " files");
        return;
    }

    // Detect new files
    for (const auto& [path, state] : current) {
        auto it = baseline_.find(path);
        if (it == baseline_.end()) {
            // New file
            std::string hash = compute_file_hash(path);
            nlohmann::json details = {
                {"path", path},
                {"action", "created"},
                {"size", state.size},
                {"hash", hash}
            };

            Event e;
            e.event_id       = UUID::generate();
            e.schema_version = SCHEMA_VERSION;
            e.event_type     = "file.created";
            e.category       = Category::File;
            e.timestamp      = ts;
            e.observed_at    = ts;
            e.actor          = "";
            e.severity       = Severity::Medium;
            e.source         = path;
            e.details        = details;
            e.collector_status = "ok";

            emit(e);
            status_.events_emitted++;
        } else if (it->second.mtime != state.mtime || it->second.size != state.size) {
            // Modified file
            std::string hash = compute_file_hash(path);
            nlohmann::json details = {
                {"path", path},
                {"action", "modified"},
                {"old_size", it->second.size},
                {"new_size", state.size},
                {"hash", hash}
            };

            Event e;
            e.event_id       = UUID::generate();
            e.schema_version = SCHEMA_VERSION;
            e.event_type     = "file.modified";
            e.category       = Category::File;
            e.timestamp      = ts;
            e.observed_at    = ts;
            e.actor          = "";
            e.severity       = Severity::Medium;
            e.source         = path;
            e.details        = details;
            e.collector_status = "ok";

            emit(e);
            status_.events_emitted++;
        }
    }

    // Detect deleted files
    for (const auto& [path, state] : baseline_) {
        if (current.find(path) == current.end()) {
            nlohmann::json details = {
                {"path", path},
                {"action", "deleted"},
                {"old_size", state.size}
            };

            Event e;
            e.event_id       = UUID::generate();
            e.schema_version = SCHEMA_VERSION;
            e.event_type     = "file.deleted";
            e.category       = Category::File;
            e.timestamp      = ts;
            e.observed_at    = ts;
            e.actor          = "";
            e.severity       = Severity::High;
            e.source         = path;
            e.details        = details;
            e.collector_status = "ok";

            emit(e);
            status_.events_emitted++;
        }
    }

    baseline_ = current;
    status_.last_collect = ts;
}

CollectorStatus FileCollector::status() const {
    return status_;
}

} // namespace skynet
