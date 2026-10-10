// SkyNet — Application Collector Implementation
// Monitors web server logs, database errors, browser extensions, cron jobs,
// autostart entries, suspicious downloads, and mic/camera access.

#include "skynet/collectors/app_collector.h"
#include "skynet/utils/logger.h"
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <sys/stat.h>
#include <regex>
#include <unistd.h>
#include <pwd.h>
#include <cstring>
#include <algorithm>

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

bool AppCollector::init(const Config& config) {
    enabled_ = config.enable_app;
    if (!enabled_) return true;

    status_.enabled = true;

    // Init nginx log watcher if the file exists
    struct stat st{};
    if (stat(config.nginx_log_path.c_str(), &st) == 0) {
        nginx_watcher_ = std::make_unique<FileWatcher>(config.nginx_log_path);
    }

    // Init mysql log watcher if the file exists
    if (stat(config.mysql_log_path.c_str(), &st) == 0) {
        mysql_watcher_ = std::make_unique<FileWatcher>(config.mysql_log_path);
    }

    status_.accessible = true;
    return true;
}

void AppCollector::check_nginx_logs(const EventCallback& emit) {
    if (!nginx_watcher_) return;

    static int error_404_count = 0;
    static std::string last_reset_minute;

    std::string ts = now_utc();
    std::string current_minute = ts.substr(0, 16); // YYYY-MM-DDTHH:MM

    if (current_minute != last_reset_minute) {
        error_404_count = 0;
        last_reset_minute = current_minute;
    }

    nginx_watcher_->poll([&](const std::string& line) {
        // Look for HTTP status codes
        // Common log format: IP - - [date] "METHOD URI HTTP/1.1" STATUS SIZE
        static std::regex re_status(R"(\s(\d{3})\s\d+\s)");
        std::smatch m;
        if (std::regex_search(line, m, re_status)) {
            int status_code = std::stoi(m[1].str());

            if (status_code == 404) {
                error_404_count++;
                // Many 404s = directory enumeration / scanning
                if (error_404_count > 20) {
                    nlohmann::json details = {
                        {"service", "nginx"},
                        {"error_type", "excessive_404"},
                        {"count", error_404_count},
                        {"sample_line", line.substr(0, 200)}
                    };

                    Event e;
                    e.event_id = UUID::generate(); e.schema_version = SCHEMA_VERSION;
                    e.event_type = "application.web_scan_detected";
                    e.category = Category::Application;
                    e.timestamp = ts; e.observed_at = ts;
                    e.actor = ""; e.severity = Severity::High;
                    e.source = nginx_watcher_->path();
                    e.details = details; e.collector_status = "ok";
                    emit(e);
                    status_.events_emitted++;
                    error_404_count = 0; // Reset after alert
                }
            } else if (status_code >= 500) {
                nlohmann::json details = {
                    {"service", "nginx"},
                    {"status_code", status_code},
                    {"error_type", "server_error"},
                    {"line", line.substr(0, 200)}
                };

                Event e;
                e.event_id = UUID::generate(); e.schema_version = SCHEMA_VERSION;
                e.event_type = "application.server_error";
                e.category = Category::Application;
                e.timestamp = ts; e.observed_at = ts;
                e.actor = ""; e.severity = Severity::Medium;
                e.source = nginx_watcher_->path();
                e.details = details; e.collector_status = "ok";
                emit(e);
                status_.events_emitted++;
            }
        }
    });
}

// MySQL log monitoring
void AppCollector::check_mysql_logs(const EventCallback& emit) {
    if (!mysql_watcher_) return;

    mysql_watcher_->poll([&](const std::string& line) {
        // Look for authentication failures and errors
        static std::regex re_auth_fail(R"(Access denied for user '(\S+)')", std::regex::icase);
        static std::regex re_error(R"(\[ERROR\])", std::regex::icase);

        std::smatch m;
        std::string ts = now_utc();

        if (std::regex_search(line, m, re_auth_fail)) {
            nlohmann::json details = {
                {"service", "mysql"},
                {"user", m[1].str()},
                {"error_type", "db_auth_failure"}
            };

            Event e;
            e.event_id = UUID::generate(); e.schema_version = SCHEMA_VERSION;
            e.event_type = "application.db_auth_failure";
            e.category = Category::Application;
            e.timestamp = ts; e.observed_at = ts;
            e.actor = "db_user=" + m[1].str(); e.severity = Severity::Medium;
            e.source = mysql_watcher_->path();
            e.details = details; e.collector_status = "ok";
            emit(e);
            status_.events_emitted++;
        }
    });
}

// Cron job changes
std::vector<AppCollector::CronEntry> AppCollector::scan_cron_entries() {
    std::vector<CronEntry> entries;

    // System crontabs
    std::vector<std::string> cron_dirs = {
        "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly",
        "/etc/cron.weekly", "/etc/cron.monthly"
    };

    for (const auto& dir : cron_dirs) {
        DIR* d = opendir(dir.c_str());
        if (!d) continue;
        struct dirent* entry;
        while ((entry = readdir(d)) != nullptr) {
            if (entry->d_name[0] == '.') continue;
            std::string path = dir + "/" + entry->d_name;
            std::ifstream f(path);
            std::string line;
            while (std::getline(f, line)) {
                if (!line.empty() && line[0] != '#') {
                    entries.push_back({"system", "", line});
                }
            }
        }
        closedir(d);
    }

    // User crontabs
    DIR* spool = opendir("/var/spool/cron/crontabs");
    if (spool) {
        struct dirent* entry;
        while ((entry = readdir(spool)) != nullptr) {
            if (entry->d_name[0] == '.') continue;
            std::string path = std::string("/var/spool/cron/crontabs/") + entry->d_name;
            std::ifstream f(path);
            std::string line;
            while (std::getline(f, line)) {
                if (!line.empty() && line[0] != '#') {
                    entries.push_back({entry->d_name, "", line});
                }
            }
        }
        closedir(spool);
    }

    return entries;
}

void AppCollector::check_cron_changes(const EventCallback& emit) {
    auto current = scan_cron_entries();
    std::string ts = now_utc();

    if (!baseline_initialized_) return; // Will be initialized below

    // Simple comparison: check if any new entries appeared
    if (current.size() > known_crons_.size()) {
        nlohmann::json details = {
            {"old_count", known_crons_.size()},
            {"new_count", current.size()},
            {"change_type", "cron_added"}
        };

        Event e;
        e.event_id = UUID::generate(); e.schema_version = SCHEMA_VERSION;
        e.event_type = "application.cron_changed";
        e.category = Category::Application;
        e.timestamp = ts; e.observed_at = ts;
        e.actor = ""; e.severity = Severity::High;
        e.source = "/etc/cron*, /var/spool/cron";
        e.details = details; e.collector_status = "ok";
        emit(e);
        status_.events_emitted++;
    }

    known_crons_ = current;
}

// Browser extensions
std::set<std::string> AppCollector::scan_browser_extensions() {
    std::set<std::string> extensions;

    // Get all home directories
    std::vector<std::string> homes;
    struct passwd* pw;
    setpwent();
    while ((pw = getpwent()) != nullptr) {
        if (pw->pw_uid >= 1000 || pw->pw_uid == 0) {
            homes.push_back(pw->pw_dir);
        }
    }
    endpwent();

    for (const auto& home : homes) {
        // Chrome extensions
        std::string chrome_ext = home + "/.config/google-chrome/Default/Extensions";
        DIR* d = opendir(chrome_ext.c_str());
        if (d) {
            struct dirent* entry;
            while ((entry = readdir(d)) != nullptr) {
                if (entry->d_name[0] != '.' && entry->d_type == DT_DIR) {
                    extensions.insert(std::string("chrome:") + entry->d_name);
                }
            }
            closedir(d);
        }

        // Firefox extensions
        std::string ff_base = home + "/.mozilla/firefox";
        DIR* ff = opendir(ff_base.c_str());
        if (ff) {
            struct dirent* entry;
            while ((entry = readdir(ff)) != nullptr) {
                std::string name = entry->d_name;
                if (name.find(".default") != std::string::npos) {
                    std::string ext_dir = ff_base + "/" + name + "/extensions";
                    DIR* ext = opendir(ext_dir.c_str());
                    if (ext) {
                        struct dirent* e2;
                        while ((e2 = readdir(ext)) != nullptr) {
                            if (e2->d_name[0] != '.') {
                                extensions.insert(std::string("firefox:") + e2->d_name);
                            }
                        }
                        closedir(ext);
                    }
                }
            }
            closedir(ff);
        }

        // Edge extensions
        std::string edge_ext = home + "/.config/microsoft-edge/Default/Extensions";
        d = opendir(edge_ext.c_str());
        if (d) {
            struct dirent* entry;
            while ((entry = readdir(d)) != nullptr) {
                if (entry->d_name[0] != '.' && entry->d_type == DT_DIR) {
                    extensions.insert(std::string("edge:") + entry->d_name);
                }
            }
            closedir(d);
        }
    }

    return extensions;
}

void AppCollector::check_browser_extensions(const EventCallback& emit) {
    auto current = scan_browser_extensions();
    std::string ts = now_utc();

    if (!baseline_initialized_) return;

    for (const auto& ext : current) {
        if (known_extensions_.find(ext) == known_extensions_.end()) {
            nlohmann::json details = {
                {"extension_id", ext},
                {"action", "new_extension"}
            };

            Event e;
            e.event_id = UUID::generate(); e.schema_version = SCHEMA_VERSION;
            e.event_type = "application.browser_extension_added";
            e.category = Category::Application;
            e.timestamp = ts; e.observed_at = ts;
            e.actor = ""; e.severity = Severity::Medium;
            e.source = "browser_profile";
            e.details = details; e.collector_status = "ok";
            emit(e);
            status_.events_emitted++;
        }
    }

    known_extensions_ = current;
}

// Autostart persistence
std::set<std::string> AppCollector::scan_autostart_files() {
    std::set<std::string> files;

    struct passwd* pw;
    setpwent();
    while ((pw = getpwent()) != nullptr) {
        if (pw->pw_uid >= 1000 || pw->pw_uid == 0) {
            std::string home = pw->pw_dir;

            // .bashrc
            std::string bashrc = home + "/.bashrc";
            struct stat st{};
            if (stat(bashrc.c_str(), &st) == 0) {
                files.insert(bashrc + ":" + std::to_string(st.st_mtime));
            }

            // autostart directory
            std::string autostart = home + "/.config/autostart";
            DIR* d = opendir(autostart.c_str());
            if (d) {
                struct dirent* entry;
                while ((entry = readdir(d)) != nullptr) {
                    if (entry->d_name[0] != '.') {
                        std::string path = autostart + "/" + entry->d_name;
                        if (stat(path.c_str(), &st) == 0) {
                            files.insert(path + ":" + std::to_string(st.st_mtime));
                        }
                    }
                }
                closedir(d);
            }
        }
    }
    endpwent();

    return files;
}

void AppCollector::check_autostart(const EventCallback& emit) {
    auto current = scan_autostart_files();
    std::string ts = now_utc();

    if (!baseline_initialized_) return;

    for (const auto& entry : current) {
        if (known_autostart_.find(entry) == known_autostart_.end()) {
            // Extract path (before the colon)
            std::string path = entry.substr(0, entry.rfind(':'));

            nlohmann::json details = {
                {"path", path},
                {"action", "autostart_changed"}
            };

            Event e;
            e.event_id = UUID::generate(); e.schema_version = SCHEMA_VERSION;
            e.event_type = "application.autostart_changed";
            e.category = Category::Application;
            e.timestamp = ts; e.observed_at = ts;
            e.actor = ""; e.severity = Severity::High;
            e.source = path;
            e.details = details; e.collector_status = "ok";
            emit(e);
            status_.events_emitted++;
        }
    }

    known_autostart_ = current;
}

// Suspicious downloads
void AppCollector::check_suspicious_downloads(const EventCallback& emit) {
    std::string ts = now_utc();

    struct passwd* pw;
    setpwent();
    while ((pw = getpwent()) != nullptr) {
        if (pw->pw_uid < 1000) continue;

        std::string downloads = std::string(pw->pw_dir) + "/Downloads";
        DIR* d = opendir(downloads.c_str());
        if (!d) continue;

        struct dirent* entry;
        while ((entry = readdir(d)) != nullptr) {
            std::string name = entry->d_name;
            // Check for suspicious file extensions with execute permissions
            if (name.find(".sh") != std::string::npos ||
                name.find(".elf") != std::string::npos ||
                name.find(".bin") != std::string::npos) {

                std::string path = downloads + "/" + name;
                struct stat st{};
                if (stat(path.c_str(), &st) == 0 && (st.st_mode & S_IXUSR)) {
                    nlohmann::json details = {
                        {"path", path},
                        {"filename", name},
                        {"size", st.st_size},
                        {"executable", true}
                    };

                    Event e;
                    e.event_id = UUID::generate(); e.schema_version = SCHEMA_VERSION;
                    e.event_type = "application.suspicious_download";
                    e.category = Category::Application;
                    e.timestamp = ts; e.observed_at = ts;
                    e.actor = "user=" + std::string(pw->pw_name);
                    e.severity = Severity::High;
                    e.source = path;
                    e.details = details; e.collector_status = "ok";
                    emit(e);
                    status_.events_emitted++;
                }
            }
        }
        closedir(d);
    }
    endpwent();
}

// Mic/camera access
void AppCollector::check_media_access(const EventCallback& emit) {
    std::string ts = now_utc();

    // Check if /dev/video* or /dev/snd/* are opened by processes
    std::vector<std::string> media_devices = {"/dev/video0", "/dev/snd/pcmC0D0c"};

    for (const auto& dev : media_devices) {
        struct stat st{};
        if (stat(dev.c_str(), &st) != 0) continue;

        // Use lsof-like approach via /proc/*/fd
        DIR* proc_dir = opendir("/proc");
        if (!proc_dir) continue;

        struct dirent* entry;
        while ((entry = readdir(proc_dir)) != nullptr) {
            if (entry->d_type != DT_DIR) continue;
            bool is_pid = true;
            for (const char* c = entry->d_name; *c; ++c) {
                if (!isdigit(*c)) { is_pid = false; break; }
            }
            if (!is_pid) continue;

            std::string fd_dir = std::string("/proc/") + entry->d_name + "/fd";
            DIR* fds = opendir(fd_dir.c_str());
            if (!fds) continue;

            struct dirent* fd_entry;
            while ((fd_entry = readdir(fds)) != nullptr) {
                char link_buf[PATH_MAX];
                std::string fd_path = fd_dir + "/" + fd_entry->d_name;
                ssize_t len = readlink(fd_path.c_str(), link_buf, sizeof(link_buf) - 1);
                if (len > 0) {
                    link_buf[len] = '\0';
                    if (std::string(link_buf) == dev) {
                        nlohmann::json details = {
                            {"device", dev},
                            {"pid", std::string(entry->d_name)},
                            {"access_type", dev.find("video") != std::string::npos ? "camera" : "microphone"}
                        };

                        Event e;
                        e.event_id = UUID::generate(); e.schema_version = SCHEMA_VERSION;
                        e.event_type = "application.media_access";
                        e.category = Category::Application;
                        e.timestamp = ts; e.observed_at = ts;
                        e.actor = "pid=" + std::string(entry->d_name);
                        e.severity = Severity::Medium;
                        e.source = dev;
                        e.details = details; e.collector_status = "ok";
                        emit(e);
                        status_.events_emitted++;
                    }
                }
            }
            closedir(fds);
        }
        closedir(proc_dir);
    }
}

void AppCollector::collect(const EventCallback& emit) {
    if (!enabled_) return;

    if (!baseline_initialized_) {
        known_crons_ = scan_cron_entries();
        known_extensions_ = scan_browser_extensions();
        known_autostart_ = scan_autostart_files();
        baseline_initialized_ = true;
        LOG_INFO("app", "Application baseline established");
    }

    check_nginx_logs(emit);
    check_mysql_logs(emit);
    check_cron_changes(emit);
    check_browser_extensions(emit);
    check_autostart(emit);
    check_suspicious_downloads(emit);
    check_media_access(emit);

    status_.last_collect = now_utc();
}

CollectorStatus AppCollector::status() const {
    return status_;
}

} // namespace skynet
