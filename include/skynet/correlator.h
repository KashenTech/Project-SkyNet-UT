#pragma once
// SkyNet — Correlation Engine
// Local preprocessor that detects multi-event attack sequences.
// Rules: brute-force→success, new-account→privilege, USB→execution,
//        web→shell, download→run, log tampering.

#include "types.h"
#include <vector>
#include <deque>
#include <string>
#include <functional>
#include <chrono>
#include <map>

namespace skynet {

using AlertCallback = std::function<void(Alert)>;

class Correlator {
public:
    /// Feed an event into the correlation engine.
    void process(const Event& event, const AlertCallback& on_alert);

    /// Get rule descriptions for documentation.
    static std::vector<std::pair<std::string, std::string>> rule_descriptions();

private:
    // Sliding window of recent events for correlation (max 10000)
    std::deque<Event> window_;
    static constexpr size_t MAX_WINDOW = 10000;
    static constexpr int WINDOW_SECONDS = 300; // 5 minute correlation window

    // Internal tracking state for rules
    struct BruteForceState {
        std::vector<std::string> event_ids;
        std::string first_seen;
        int count = 0;
    };
    std::map<std::string, BruteForceState> brute_force_tracker_;

    struct NewAccountState {
        std::string event_id;
        std::string account;
        std::string timestamp;
    };
    std::vector<NewAccountState> new_accounts_;

    struct USBState {
        std::string plug_event_id;
        std::string mount_event_id;
        std::string device_id;
        std::string mount_path;
        std::string timestamp;
        bool mounted = false;
    };
    std::map<std::string, USBState> usb_tracker_;

    // Rule implementations
    void rule_brute_force_success(const Event& event, const AlertCallback& on_alert);
    void rule_account_persistence(const Event& event, const AlertCallback& on_alert);
    void rule_usb_execution(const Event& event, const AlertCallback& on_alert);
    void rule_web_to_shell(const Event& event, const AlertCallback& on_alert);
    void rule_download_to_run(const Event& event, const AlertCallback& on_alert);
    void rule_log_tampering(const Event& event, const AlertCallback& on_alert);

    void trim_window();
    Alert make_alert(const std::string& rule_id, Severity sev, double confidence,
                     const std::string& explanation,
                     const std::vector<std::string>& event_ids,
                     const std::string& first_seen, const std::string& last_seen);
};

} // namespace skynet
