// SkyNet — Transport Implementation
// Writes batched events, alerts, and host metadata to files.

#include "skynet/transport.h"
#include "skynet/utils/logger.h"
#include <fstream>
#include <sstream>
#include <sys/stat.h>

#if defined(_WIN32)
#include <direct.h>
#define mkdir_compat(dir) _mkdir(dir)
#else
#include <unistd.h>
#define mkdir_compat(dir) mkdir(dir, 0755)
#endif

namespace skynet {

void Transport::init(const Config& config) {
    output_file_ = config.output_file;
    alerts_file_ = config.alerts_file;

    ensure_directory(output_file_);
    ensure_directory(alerts_file_);

    LOG_INFO("transport", "Initialized output_file=" + output_file_ + " alerts_file=" + alerts_file_);
}

bool Transport::send_events(const std::vector<Event>& events) {
    if (events.empty()) return true;

    std::vector<nlohmann::json> lines;
    lines.reserve(events.size());
    for (const auto& e : events) {
        nlohmann::json j;
        to_json(j, e);
        lines.push_back(std::move(j));
    }

    bool ok = append_json_lines(output_file_, lines);
    if (ok) {
        healthy_ = true;
        total_sent_ += events.size();
        LOG_INFO("transport", "Wrote " + std::to_string(events.size()) + " events to " + output_file_);
    } else {
        healthy_ = false;
        total_failed_ += events.size();
        LOG_ERROR("transport", "Failed to write " + std::to_string(events.size()) + " events to " + output_file_);
    }
    return ok;
}

bool Transport::send_alerts(const std::vector<Alert>& alerts) {
    if (alerts.empty()) return true;

    std::vector<nlohmann::json> lines;
    lines.reserve(alerts.size());
    for (const auto& a : alerts) {
        nlohmann::json j;
        to_json(j, a);
        lines.push_back(std::move(j));
    }

    bool ok = append_json_lines(alerts_file_, lines);
    if (ok) {
        LOG_INFO("transport", "Wrote " + std::to_string(alerts.size()) + " alerts to " + alerts_file_);
    } else {
        LOG_ERROR("transport", "Failed to write alerts to " + alerts_file_);
    }
    return ok;
}

bool Transport::send_host_info(const HostInfo& info) {
    nlohmann::json j;
    to_json(j, info);
    // Write host info alongside events or to its own file if path directory exists
    std::string host_path = output_file_;
    auto last_slash = host_path.find_last_of("/\\");
    if (last_slash != std::string::npos) {
        host_path = host_path.substr(0, last_slash + 1) + "host.json";
    } else {
        host_path = "host.json";
    }

    return write_json_file(host_path, j);
}

bool Transport::append_json_lines(const std::string& path, const std::vector<nlohmann::json>& lines) {
    std::lock_guard<std::mutex> lock(write_mtx_);
    ensure_directory(path);

    std::ofstream f(path, std::ios::app);
    if (!f.is_open()) return false;

    for (const auto& item : lines) {
        f << item.dump() << "\n";
    }
    f.flush();
    return f.good();
}

bool Transport::write_json_file(const std::string& path, const nlohmann::json& data) {
    std::lock_guard<std::mutex> lock(write_mtx_);
    ensure_directory(path);

    std::ofstream f(path, std::ios::trunc);
    if (!f.is_open()) return false;

    f << data.dump(2) << "\n";
    f.flush();
    return f.good();
}

void Transport::ensure_directory(const std::string& file_path) {
    auto last_slash = file_path.find_last_of("/\\");
    if (last_slash == std::string::npos) return;

    std::string dir = file_path.substr(0, last_slash);
    std::string current;
    for (size_t i = 0; i < dir.length(); ++i) {
        current += dir[i];
        if (dir[i] == '/' || dir[i] == '\\' || i == dir.length() - 1) {
            if (current != "/" && current != "\\" && !current.empty()) {
                mkdir_compat(current.c_str());
            }
        }
    }
}

} // namespace skynet
