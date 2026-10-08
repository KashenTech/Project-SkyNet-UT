// SkyNet — System Collector Implementation
// Monitors system errors, crashes, OOM kills, log tampering.

#include "skynet/collectors/system_collector.h"
#include "skynet/utils/logger.h"
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <sys/stat.h>
#include <regex>
#include <cstdio>
#include <array>
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

bool SystemCollector::init(const Config& config) {
    enabled_ = config.enable_system;
    if (!enabled_) return true;

    syslog_watcher_ = std::make_unique<FileWatcher>(config.syslog_path);
    status_.enabled = true;
    status_.accessible = syslog_watcher_->accessible();

    // Set up monitored log files for tamper detection
    monitored_logs_ = {
        config.auth_log_path,
        config.syslog_path,
        "/var/log/kern.log",
        "/var/log/daemon.log"
    };

    // Initialize baselines
    for (const auto& path : monitored_logs_) {
        struct stat st{};
        if (stat(path.c_str(), &st) == 0) {
            log_baselines_[path] = {st.st_size, st.st_ino};
        }
    }

    return true;
}

void SystemCollector::parse_syslog_line(const std::string& line, const EventCallback& emit) {
    std::string ts = now_utc();

    // Segfault
    static std::regex re_segfault(
        R"((\w+\s+\d+\s+[\d:]+)\s+\S+\s+kernel:\s+\[.*\]\s+(\S+)\[\d+\]:\s+segfault)",
        std::regex::icase);

    // Out of memory kill
    static std::regex re_oom(
        R"((\w+\s+\d+\s+[\d:]+)\s+\S+\s+kernel:\s+.*Out of memory.*Killed process\s+\d+\s+\((\S+)\))",
        std::regex::icase);

    // Service failure
    static std::regex re_service_fail(
        R"((\w+\s+\d+\s+[\d:]+)\s+\S+\s+systemd\[\d+\]:\s+(\S+).*(?:failed|Failed))",
        std::regex::icase);

    // Permission denied
    static std::regex re_denied(
        R"((\w+\s+\d+\s+[\d:]+)\s+\S+\s+.*(?:permission denied|Operation not permitted).*?(\S+))",
        std::regex::icase);

    std::smatch m;

    if (std::regex_search(line, m, re_segfault)) {
        nlohmann::json details = {
            {"process", m[2].str()},
            {"error_type", "segfault"}
        };
        Event e;
        e.event_id = UUID::generate(); e.schema_version = SCHEMA_VERSION;
        e.event_type = "system.segfault"; e.category = Category::Error;
        e.timestamp = ts; e.observed_at = ts;
        e.actor = "process=" + m[2].str(); e.severity = Severity::High;
        e.source = "/var/log/syslog"; e.details = details;
        e.collector_status = "ok";
        emit(e);
        status_.events_emitted++;
        return;
    }

    if (std::regex_search(line, m, re_oom)) {
        nlohmann::json details = {
            {"process", m[2].str()},
            {"error_type", "oom_kill"}
        };
        Event e;
        e.event_id = UUID::generate(); e.schema_version = SCHEMA_VERSION;
        e.event_type = "system.oom_kill"; e.category = Category::Error;
        e.timestamp = ts; e.observed_at = ts;
        e.actor = "process=" + m[2].str(); e.severity = Severity::High;
        e.source = "/var/log/syslog"; e.details = details;
        e.collector_status = "ok";
        emit(e);
        status_.events_emitted++;
        return;
    }

    if (std::regex_search(line, m, re_service_fail)) {
        nlohmann::json details = {
            {"service", m[2].str()},
            {"error_type", "service_failure"}
        };
        Event e;
        e.event_id = UUID::generate(); e.schema_version = SCHEMA_VERSION;
        e.event_type = "system.service_failure"; e.category = Category::Error;
        e.timestamp = ts; e.observed_at = ts;
        e.actor = "service=" + m[2].str(); e.severity = Severity::Medium;
        e.source = "/var/log/syslog"; e.details = details;
        e.collector_status = "ok";
        emit(e);
        status_.events_emitted++;
        return;
    }

    if (std::regex_search(line, m, re_denied)) {
        nlohmann::json details = {
            {"subject", m[2].str()},
            {"error_type", "permission_denied"}
        };
        Event e;
        e.event_id = UUID::generate(); e.schema_version = SCHEMA_VERSION;
        e.event_type = "system.permission_denied"; e.category = Category::Error;
        e.timestamp = ts; e.observed_at = ts;
        e.actor = m[2].str(); e.severity = Severity::Medium;
        e.source = "/var/log/syslog"; e.details = details;
        e.collector_status = "ok";
        emit(e);
        status_.events_emitted++;
    }
}

void SystemCollector::check_log_tampering(const EventCallback& emit) {
    std::string ts = now_utc();

    for (const auto& path : monitored_logs_) {
        struct stat st{};
        if (stat(path.c_str(), &st) != 0) {
            // Log file disappeared
            if (log_baselines_.find(path) != log_baselines_.end()) {
                nlohmann::json details = {
                    {"path", path},
                    {"action", "log_disappeared"},
                    {"error_type", "log_tampering"}
                };
                Event e;
                e.event_id = UUID::generate(); e.schema_version = SCHEMA_VERSION;
                e.event_type = "system.log_tampering"; e.category = Category::Error;
                e.timestamp = ts; e.observed_at = ts;
                e.actor = ""; e.severity = Severity::Critical;
                e.source = path; e.details = details;
                e.collector_status = "ok";
                emit(e);
                status_.events_emitted++;
            }
            continue;
        }

        auto it = log_baselines_.find(path);
        if (it != log_baselines_.end()) {
            // Log file shrunk (cleared)
            if (st.st_size < it->second.last_size) {
                nlohmann::json details = {
                    {"path", path},
                    {"action", "log_shrunk"},
                    {"old_size", it->second.last_size},
                    {"new_size", st.st_size},
                    {"error_type", "log_tampering"}
                };
                Event e;
                e.event_id = UUID::generate(); e.schema_version = SCHEMA_VERSION;
                e.event_type = "system.log_tampering"; e.category = Category::Error;
                e.timestamp = ts; e.observed_at = ts;
                e.actor = ""; e.severity = Severity::Critical;
                e.source = path; e.details = details;
                e.collector_status = "ok";
                emit(e);
                status_.events_emitted++;
            }
            // Inode changed (file replaced)
            if (st.st_ino != it->second.last_inode && it->second.last_inode != 0) {
                nlohmann::json details = {
                    {"path", path},
                    {"action", "log_replaced"},
                    {"error_type", "log_tampering"}
                };
                Event e;
                e.event_id = UUID::generate(); e.schema_version = SCHEMA_VERSION;
                e.event_type = "system.log_tampering"; e.category = Category::Error;
                e.timestamp = ts; e.observed_at = ts;
                e.actor = ""; e.severity = Severity::Critical;
                e.source = path; e.details = details;
                e.collector_status = "ok";
                emit(e);
                status_.events_emitted++;
            }
        }

        log_baselines_[path] = {st.st_size, st.st_ino};
    }
}

void SystemCollector::check_dmesg(const EventCallback& emit) {
    // Read recent dmesg output for kernel-level errors
    std::array<char, 256> buffer;
    std::string result;

    FILE* pipe = popen("dmesg --level=err,crit,alert,emerg -T 2>/dev/null | tail -20", "r");
    if (!pipe) return;

    while (fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    pclose(pipe);

    // Simple parsing of dmesg errors (already handled segfaults above)
    // This is supplementary
}

void SystemCollector::collect(const EventCallback& emit) {
    if (!enabled_) return;

    // Parse new syslog lines
    if (syslog_watcher_) {
        syslog_watcher_->poll([&](const std::string& line) {
            parse_syslog_line(line, emit);
        });
    }

    // Check for log tampering
    check_log_tampering(emit);

    status_.last_collect = now_utc();
    status_.accessible = true;
}

CollectorStatus SystemCollector::status() const {
    return status_;
}

} // namespace skynet
