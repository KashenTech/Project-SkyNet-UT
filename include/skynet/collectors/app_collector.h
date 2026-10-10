#pragma once
// SkyNet — Application Collector
// Monitors web server logs, database errors, browser extensions,
// cron jobs, autostart entries, suspicious downloads, mic/camera access.

#include "collector.h"
#include "../utils/file_watcher.h"
#include "../utils/uuid.h"
#include <set>
#include <map>

namespace skynet {

class AppCollector : public Collector {
public:
    std::string name() const override { return "app"; }
    bool enabled() const override { return enabled_; }
    bool init(const Config& config) override;
    void collect(const EventCallback& emit) override;
    CollectorStatus status() const override;

private:
    bool enabled_ = true;
    CollectorStatus status_{"app"};

    std::unique_ptr<FileWatcher> nginx_watcher_;
    std::unique_ptr<FileWatcher> mysql_watcher_;

    // Cron / autostart baselines
    struct CronEntry {
        std::string user;
        std::string schedule;
        std::string command;
    };
    std::vector<CronEntry> known_crons_;
    std::set<std::string> known_extensions_;   // browser extension IDs
    std::set<std::string> known_autostart_;    // autostart file paths
    bool baseline_initialized_ = false;

    void check_nginx_logs(const EventCallback& emit);
    void check_mysql_logs(const EventCallback& emit);
    void check_cron_changes(const EventCallback& emit);
    void check_browser_extensions(const EventCallback& emit);
    void check_autostart(const EventCallback& emit);
    void check_suspicious_downloads(const EventCallback& emit);
    void check_media_access(const EventCallback& emit);

    std::vector<CronEntry> scan_cron_entries();
    std::set<std::string> scan_browser_extensions();
    std::set<std::string> scan_autostart_files();
};

} // namespace skynet
