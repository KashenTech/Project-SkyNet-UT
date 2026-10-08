// SkyNet — Correlation Engine Implementation
// Detects multi-event attack sequences from the telemetry stream.

#include "skynet/correlator.h"
#include "skynet/utils/uuid.h"
#include "skynet/utils/logger.h"
#include <algorithm>

namespace skynet {

Alert Correlator::make_alert(const std::string& rule_id, Severity sev, double confidence,
                              const std::string& explanation,
                              const std::vector<std::string>& event_ids,
                              const std::string& first_seen, const std::string& last_seen) {
    Alert a;
    a.alert_id          = UUID::generate();
    a.rule_id           = rule_id;
    a.severity          = sev;
    a.confidence        = confidence;
    a.explanation       = explanation;
    a.first_seen        = first_seen;
    a.last_seen         = last_seen;
    a.related_event_ids = event_ids;
    return a;
}

void Correlator::trim_window() {
    while (window_.size() > MAX_WINDOW) {
        window_.pop_front();
    }
}

void Correlator::process(const Event& event, const AlertCallback& on_alert) {
    window_.push_back(event);
    trim_window();

    // Run all correlation rules
    rule_brute_force_success(event, on_alert);
    rule_account_persistence(event, on_alert);
    rule_usb_execution(event, on_alert);
    rule_web_to_shell(event, on_alert);
    rule_download_to_run(event, on_alert);
    rule_log_tampering(event, on_alert);
}

// Rule 1: Brute-force followed by successful login
// Trigger: 5 or more failed logins from same IP/user followed by a success
void Correlator::rule_brute_force_success(const Event& event, const AlertCallback& on_alert) {
    if (event.event_type == "auth.login_failed") {
        std::string ip = event.details.value("ip", "");
        std::string user = event.details.value("user", "");
        std::string key = ip + "|" + user;

        auto& state = brute_force_tracker_[key];
        state.event_ids.push_back(event.event_id);
        state.count++;
        if (state.first_seen.empty()) state.first_seen = event.timestamp;
        return;
    }

    if (event.event_type == "auth.login_success" || event.event_type == "auth.root_login") {
        std::string ip = event.details.value("ip", "");
        std::string user = event.details.value("user", "");
        std::string key = ip + "|" + user;

        auto it = brute_force_tracker_.find(key);
        if (it != brute_force_tracker_.end() && it->second.count >= 5) {
            auto& state = it->second;
            state.event_ids.push_back(event.event_id);

            std::string explanation =
                "Brute-force attack detected: " + std::to_string(state.count) +
                " failed login attempts from IP " + ip + " for user '" + user +
                "' followed by a successful login. This indicates a password was guessed.";

            on_alert(make_alert(
                "brute_force_success",
                Severity::Critical,
                0.95,
                explanation,
                state.event_ids,
                state.first_seen,
                event.timestamp
            ));

            LOG_WARN("correlator", "ALERT: Brute-force→success for " + key);
        }

        // Clear tracker for this key after checking
        brute_force_tracker_.erase(key);
    }
}

// Rule 2: New account followed by privilege escalation
// Trigger: auth.user_created followed by auth.group_change to sudo/admin
void Correlator::rule_account_persistence(const Event& event, const AlertCallback& on_alert) {
    if (event.event_type == "auth.user_created") {
        NewAccountState state;
        state.event_id = event.event_id;
        state.account  = event.details.value("account", "");
        state.timestamp = event.timestamp;
        new_accounts_.push_back(state);
        return;
    }

    if (event.event_type == "auth.group_change") {
        std::string account = event.details.value("account", "");
        std::string group   = event.details.value("group", "");

        // Only alert on privilege-granting groups
        if (group != "sudo" && group != "wheel" && group != "admin") return;

        for (auto it = new_accounts_.begin(); it != new_accounts_.end(); ++it) {
            if (it->account == account) {
                std::string explanation =
                    "Account persistence detected: User '" + account +
                    "' was created and then immediately added to the '" + group +
                    "' group. This is a common attacker pattern for establishing "
                    "persistent privileged access.";

                on_alert(make_alert(
                    "account_persistence",
                    Severity::Critical,
                    0.90,
                    explanation,
                    {it->event_id, event.event_id},
                    it->timestamp,
                    event.timestamp
                ));

                LOG_WARN("correlator", "ALERT: Account persistence for " + account);
                new_accounts_.erase(it);
                return;
            }
        }
    }
}

// Rule 3: USB plug -> mount -> execution from mount path
// Trigger: usb.device_connected -> usb.drive_mounted -> process.started from /media or /mnt
void Correlator::rule_usb_execution(const Event& event, const AlertCallback& on_alert) {
    if (event.event_type == "usb.device_connected") {
        std::string device_id = event.details.value("vendor_id", "") + ":" +
                                event.details.value("product_id", "");
        USBState state;
        state.plug_event_id = event.event_id;
        state.device_id     = device_id;
        state.timestamp     = event.timestamp;
        usb_tracker_[device_id] = state;
        return;
    }

    if (event.event_type == "usb.drive_mounted") {
        std::string mount_point = event.details.value("mount_point", "");
        // Associate this mount with a recent USB plug event
        for (auto& [id, state] : usb_tracker_) {
            if (!state.mounted) {
                state.mounted = true;
                state.mount_event_id = event.event_id;
                state.mount_path = mount_point;
                break;
            }
        }
        return;
    }

    if (event.event_type == "process.started") {
        std::string exe = event.details.value("exe", "");
        std::string cmdline = event.details.value("cmdline", "");

        for (auto it = usb_tracker_.begin(); it != usb_tracker_.end(); ++it) {
            if (!it->second.mounted) continue;

            // Check if the process was launched from the USB mount path
            if (exe.find(it->second.mount_path) == 0 ||
                cmdline.find(it->second.mount_path) != std::string::npos) {

                std::string explanation =
                    "USB execution detected: An unknown USB device (" + it->second.device_id +
                    ") was plugged in, mounted at '" + it->second.mount_path +
                    "', and then a process was started from that path ('" + exe +
                    "'). This may indicate USB-based malware delivery.";

                on_alert(make_alert(
                    "usb_execution",
                    Severity::Critical,
                    0.85,
                    explanation,
                    {it->second.plug_event_id, it->second.mount_event_id, event.event_id},
                    it->second.timestamp,
                    event.timestamp
                ));

                LOG_WARN("correlator", "ALERT: USB execution from " + it->second.mount_path);
                usb_tracker_.erase(it);
                return;
            }
        }
    }
}

// Rule 4: Web server spawns shell
// Trigger: process.started where parent is a web server and child is a shell
void Correlator::rule_web_to_shell(const Event& event, const AlertCallback& on_alert) {
    if (event.event_type != "process.started") return;

    std::string exe  = event.details.value("exe", "");
    std::string comm = event.details.value("comm", "");
    int ppid         = event.details.value("ppid", 0);

    // Is this a shell/interpreter?
    bool is_shell = (comm == "bash" || comm == "sh" || comm == "dash" ||
                     comm == "python" || comm == "python3" || comm == "perl" ||
                     comm == "ruby" || comm == "php");
    if (!is_shell) return;

    // Check if the parent is a web server
    for (const auto& prev : window_) {
        if (prev.event_type != "process.started") continue;
        int prev_pid = prev.details.value("pid", 0);
        if (prev_pid != ppid) continue;

        std::string parent_comm = prev.details.value("comm", "");
        bool is_web = (parent_comm == "nginx" || parent_comm == "apache2" ||
                       parent_comm == "httpd" || parent_comm == "node" ||
                       parent_comm == "java" || parent_comm == "php-fpm");
        if (is_web) {
            std::string explanation =
                "Web-to-shell detected: Web server process '" + parent_comm +
                "' (PID " + std::to_string(ppid) + ") spawned a shell/interpreter '" +
                comm + "'. This typically indicates a web shell or remote code execution exploit.";

            on_alert(make_alert(
                "web_to_shell",
                Severity::Critical,
                0.90,
                explanation,
                {prev.event_id, event.event_id},
                prev.timestamp,
                event.timestamp
            ));

            LOG_WARN("correlator", "ALERT: Web→shell: " + parent_comm + " → " + comm);
            return;
        }
    }
}

// Rule 5: Download followed by execution
// Trigger: file.created in ~/Downloads followed by process.started from same path
void Correlator::rule_download_to_run(const Event& event, const AlertCallback& on_alert) {
    if (event.event_type != "process.started") return;

    std::string exe = event.details.value("exe", "");
    if (exe.find("/Downloads/") == std::string::npos) return;

    // Look for a recent file creation at this path
    for (const auto& prev : window_) {
        if (prev.event_type != "file.created" && prev.event_type != "application.suspicious_download")
            continue;

        std::string path = prev.details.value("path", "");
        if (path == exe || exe.find(path) != std::string::npos) {
            std::string explanation =
                "Download-to-run detected: File '" + path +
                "' appeared in Downloads and was subsequently executed. "
                "This may indicate a drive-by download or phishing payload.";

            on_alert(make_alert(
                "download_to_run",
                Severity::High,
                0.80,
                explanation,
                {prev.event_id, event.event_id},
                prev.timestamp,
                event.timestamp
            ));

            LOG_WARN("correlator", "ALERT: Download→run: " + path);
            return;
        }
    }
}

// Rule 6: Log tampering near another event
// Trigger: system.log_tampering event occurring near other suspicious events
void Correlator::rule_log_tampering(const Event& event, const AlertCallback& on_alert) {
    if (event.event_type != "system.log_tampering") return;

    // Look for any high-severity events in the window
    std::vector<std::string> nearby_events;
    for (const auto& prev : window_) {
        if (prev.event_id == event.event_id) continue;
        if (prev.severity >= Severity::Medium) {
            nearby_events.push_back(prev.event_id);
        }
    }

    if (!nearby_events.empty()) {
        nearby_events.push_back(event.event_id);

        std::string explanation =
            "Log tampering detected near other suspicious activity: " +
            event.details.value("path", "unknown") + " was " +
            event.details.value("action", "modified") +
            ". This may indicate an attacker covering their tracks. " +
            std::to_string(nearby_events.size() - 1) +
            " other suspicious events occurred in the same time window.";

        on_alert(make_alert(
            "log_tampering",
            Severity::Critical,
            0.85,
            explanation,
            nearby_events,
            window_.front().timestamp,
            event.timestamp
        ));

        LOG_WARN("correlator", "ALERT: Log tampering with nearby suspicious activity");
    }
}

std::vector<std::pair<std::string, std::string>> Correlator::rule_descriptions() {
    return {
        {"brute_force_success", "Failed logins followed by success from same IP/user within a window."},
        {"account_persistence", "New user followed by sudo/admin-group change."},
        {"usb_execution",       "Unknown USB plugged in, mounted, then process starts from mount path."},
        {"web_to_shell",        "Web server launches shell/interpreter."},
        {"download_to_run",     "Download followed by execution or persistence."},
        {"log_tampering",       "Log shrinks/clears or logging stops near another event."}
    };
}

} // namespace skynet
