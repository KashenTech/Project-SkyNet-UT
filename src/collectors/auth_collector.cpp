// SkyNet — Auth Collector Implementation
// Parses /var/log/auth.log for security-relevant authentication events.

#include "skynet/collectors/auth_collector.h"
#include "skynet/utils/logger.h"
#include <regex>
#include <chrono>
#include <iomanip>
#include <sstream>

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

bool AuthCollector::init(const Config& config) {
    enabled_ = config.enable_auth;
    if (!enabled_) return true;

    watcher_ = std::make_unique<FileWatcher>(config.auth_log_path);
    status_.accessible = watcher_->accessible();
    if (!status_.accessible) {
        status_.last_error = "Cannot read " + config.auth_log_path;
        LOG_WARN("auth", status_.last_error);
    }
    status_.enabled = true;
    return true;
}

Event AuthCollector::make_event(const std::string& event_type, Severity sev,
                                 const std::string& actor, const nlohmann::json& details,
                                 const std::string& timestamp) {
    Event e;
    e.event_id       = UUID::generate();
    e.schema_version = SCHEMA_VERSION;
    e.event_type     = event_type;
    e.category       = Category::Auth;
    e.timestamp      = timestamp.empty() ? now_utc() : timestamp;
    e.observed_at    = now_utc();
    e.actor          = actor;
    e.severity       = sev;
    e.source         = watcher_ ? watcher_->path() : "/var/log/auth.log";
    e.details        = details;
    e.collector_status = status_.accessible ? "ok" : "partial";
    return e;
}

void AuthCollector::parse_line(const std::string& line, const EventCallback& emit) {
    // Failed login (e.g. "Failed password for user from 192.168.1.1 port 22")
    static std::regex re_failed(
        R"((\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(\S+)\s+from\s+(\S+)\s+port\s+(\d+))",
        std::regex::icase);

    // PAM authentication failure
    static std::regex re_pam_fail(
        R"((\w+\s+\d+\s+[\d:]+)\s+\S+\s+\S+\[\d+\]:\s+pam_unix\(\S+:auth\):\s+authentication failure;.*\buser=(\S+))",
        std::regex::icase);

    // Successful login
    static std::regex re_success(
        R"((\w+\s+\d+\s+[\d:]+)\s+\S+\s+sshd\[\d+\]:\s+Accepted\s+(\S+)\s+for\s+(\S+)\s+from\s+(\S+)\s+port\s+(\d+))",
        std::regex::icase);

    // PAM session opened
    static std::regex re_session(
        R"((\w+\s+\d+\s+[\d:]+)\s+\S+\s+\S+\[\d+\]:\s+pam_unix\(\S+:session\):\s+session\s+opened\s+for\s+user\s+(\S+))",
        std::regex::icase);

    // Sudo execution
    static std::regex re_sudo(
        R"((\w+\s+\d+\s+[\d:]+)\s+\S+\s+sudo\[\d+\]:\s+(\S+)\s+:.*COMMAND=(.*))",
        std::regex::icase);

    // Account creation & group changes
    static std::regex re_useradd(
        R"((\w+\s+\d+\s+[\d:]+)\s+\S+\s+useradd\[\d+\]:\s+new user:\s+name=(\S+))",
        std::regex::icase);

    static std::regex re_usermod(
        R"((\w+\s+\d+\s+[\d:]+)\s+\S+\s+usermod\[\d+\]:\s+.*'(\S+)'\s+to\s+group\s+'(\S+)')",
        std::regex::icase);

    // Password change
    static std::regex re_passwd(
        R"((\w+\s+\d+\s+[\d:]+)\s+\S+\s+passwd\[\d+\]:\s+.*password\s+changed\s+for\s+(\S+))",
        std::regex::icase);

    std::smatch m;

    // Failed password (SSH)
    if (std::regex_search(line, m, re_failed)) {
        nlohmann::json details = {
            {"user", m[2].str()},
            {"ip", m[3].str()},
            {"port", m[4].str()},
            {"service", "sshd"},
            {"method", "password"}
        };
        emit(make_event("auth.login_failed", Severity::Medium,
                        "user=" + m[2].str(), details, ""));
        status_.events_emitted++;
        return;
    }

    // PAM authentication failure
    if (std::regex_search(line, m, re_pam_fail)) {
        nlohmann::json details = {
            {"user", m[2].str()},
            {"service", "pam"}
        };
        emit(make_event("auth.login_failed", Severity::Medium,
                        "user=" + m[2].str(), details, ""));
        status_.events_emitted++;
        return;
    }

    // Successful login
    if (std::regex_search(line, m, re_success)) {
        std::string user = m[3].str();
        Severity sev = (user == "root") ? Severity::High : Severity::Info;
        std::string etype = (user == "root") ? "auth.root_login" : "auth.login_success";

        nlohmann::json details = {
            {"user", user},
            {"ip", m[4].str()},
            {"port", m[5].str()},
            {"service", "sshd"},
            {"method", m[2].str()}
        };
        emit(make_event(etype, sev, "user=" + user, details, ""));
        status_.events_emitted++;
        return;
    }

    // Session opened
    if (std::regex_search(line, m, re_session)) {
        std::string user = m[2].str();
        nlohmann::json details = {{"user", user}};
        emit(make_event("auth.session_opened", Severity::Info,
                        "user=" + user, details, ""));
        status_.events_emitted++;
        return;
    }

    // sudo command
    if (std::regex_search(line, m, re_sudo)) {
        std::string actor = m[2].str();
        std::string command = redactor_.redact_cmdline(m[3].str());

        nlohmann::json details = {
            {"actor", actor},
            {"command", command}
        };
        emit(make_event("auth.sudo", Severity::Medium,
                        "user=" + actor, details, ""));
        status_.events_emitted++;
        return;
    }

    // New user created
    if (std::regex_search(line, m, re_useradd)) {
        nlohmann::json details = {
            {"account", m[2].str()},
            {"action", "user_created"}
        };
        emit(make_event("auth.user_created", Severity::High,
                        "account=" + m[2].str(), details, ""));
        status_.events_emitted++;
        return;
    }

    // User added to group
    if (std::regex_search(line, m, re_usermod)) {
        std::string user = m[2].str();
        std::string group = m[3].str();
        Severity sev = (group == "sudo" || group == "wheel" || group == "admin")
                        ? Severity::High : Severity::Medium;

        nlohmann::json details = {
            {"account", user},
            {"group", group},
            {"action", "group_change"}
        };
        emit(make_event("auth.group_change", sev,
                        "account=" + user, details, ""));
        status_.events_emitted++;
        return;
    }

    // Password change
    if (std::regex_search(line, m, re_passwd)) {
        nlohmann::json details = {
            {"account", m[2].str()},
            {"action", "password_changed"}
        };
        emit(make_event("auth.password_changed", Severity::Medium,
                        "account=" + m[2].str(), details, ""));
        status_.events_emitted++;
        return;
    }
}

void AuthCollector::collect(const EventCallback& emit) {
    if (!enabled_ || !watcher_) return;

    int result = watcher_->poll([&](const std::string& line) {
        parse_line(line, emit);
    });

    if (result < 0) {
        status_.accessible = false;
        status_.last_error = "Failed to read auth log";
    } else {
        status_.accessible = true;
    }
    status_.last_collect = now_utc();
}

CollectorStatus AuthCollector::status() const {
    return status_;
}

} // namespace skynet
