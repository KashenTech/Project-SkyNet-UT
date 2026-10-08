// SkyNet — Context Enricher Implementation
// Discovers host identity and enriches events with host/agent metadata.

#include "skynet/enricher.h"
#include "skynet/utils/logger.h"
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <unistd.h>

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

std::string Enricher::read_file_line(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::string line;
    std::getline(f, line);
    // Trim
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' '))
        line.pop_back();
    return line;
}

void Enricher::discover_host() {
    // Hostname
    char hostname_buf[256];
    if (gethostname(hostname_buf, sizeof(hostname_buf)) == 0) {
        host_info_.hostname = hostname_buf;
    }

    // Host ID: use machine-id for stability
    host_info_.host_id = read_file_line("/etc/machine-id");
    if (host_info_.host_id.empty()) {
        host_info_.host_id = read_file_line("/var/lib/dbus/machine-id");
    }
    if (host_info_.host_id.empty()) {
        host_info_.host_id = host_info_.hostname; // fallback
    }

    // OS info
    std::ifstream os_release("/etc/os-release");
    if (os_release.is_open()) {
        std::string line;
        while (std::getline(os_release, line)) {
            if (line.find("PRETTY_NAME=") == 0) {
                host_info_.os = line.substr(12);
                // Remove quotes
                if (!host_info_.os.empty() && host_info_.os.front() == '"')
                    host_info_.os = host_info_.os.substr(1, host_info_.os.size() - 2);
            }
            if (line.find("VERSION_ID=") == 0) {
                host_info_.os_version = line.substr(11);
                if (!host_info_.os_version.empty() && host_info_.os_version.front() == '"')
                    host_info_.os_version = host_info_.os_version.substr(1, host_info_.os_version.size() - 2);
            }
        }
    }

    // Kernel version
    host_info_.kernel = read_file_line("/proc/version");
    if (host_info_.kernel.length() > 100) {
        host_info_.kernel = host_info_.kernel.substr(0, 100);
    }

    host_info_.agent_version = "SkyNet Agent " + std::string(SCHEMA_VERSION);
    host_info_.started_at = now_utc();
}

void Enricher::init(const Config& config) {
    config_ = config;
    discover_host();

    // Override from config if specified
    if (!config.host_id.empty())  host_info_.host_id = config.host_id;
    if (!config.hostname.empty()) host_info_.hostname = config.hostname;

    LOG_INFO("enricher", "Host identity: " + host_info_.host_id + " (" + host_info_.hostname + ")");
    LOG_INFO("enricher", "OS: " + host_info_.os + " " + host_info_.os_version);
}

void Enricher::enrich(Event& event) {
    // Attach host context
    if (event.host_id.empty())   event.host_id = host_info_.host_id;
    if (event.hostname.empty())  event.hostname = host_info_.hostname;

    // Ensure schema version
    if (event.schema_version.empty()) event.schema_version = SCHEMA_VERSION;

    // Ensure observed_at is set
    if (event.observed_at.empty()) event.observed_at = now_utc();
}

} // namespace skynet
