// SkyNet — Network Collector Implementation
// Parses /proc/net/tcp, /proc/net/arp for network state monitoring.

#include "skynet/collectors/network_collector.h"
#include "skynet/utils/logger.h"
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <dirent.h>
#include <unistd.h>
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

bool NetworkCollector::init(const Config& config) {
    enabled_ = config.enable_network;
    if (!enabled_) return true;

    status_.enabled = true;
    // Check /proc/net/tcp accessibility
    std::ifstream test("/proc/net/tcp");
    status_.accessible = test.is_open();
    if (!status_.accessible) {
        status_.last_error = "/proc/net/tcp not accessible";
        LOG_WARN("network", status_.last_error);
    }
    return true;
}

std::string NetworkCollector::hex_to_ip(const std::string& hex) {
    if (hex.length() < 8) return "0.0.0.0";
    unsigned long addr = std::stoul(hex, nullptr, 16);
    return std::to_string(addr & 0xFF) + "." +
           std::to_string((addr >> 8) & 0xFF) + "." +
           std::to_string((addr >> 16) & 0xFF) + "." +
           std::to_string((addr >> 24) & 0xFF);
}

int NetworkCollector::hex_to_port(const std::string& hex) {
    return static_cast<int>(std::stoul(hex, nullptr, 16));
}

std::vector<NetworkCollector::SocketEntry> NetworkCollector::parse_proc_net_tcp(const std::string& path) {
    std::vector<SocketEntry> entries;
    std::ifstream f(path);
    if (!f.is_open()) return entries;

    std::string line;
    std::getline(f, line); // Skip header

    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string sl, local, remote, state_str, tx_rx, tr_tm, retrnsmt, uid_str, timeout, inode_str;

        iss >> sl >> local >> remote >> state_str >> tx_rx >> tr_tm >> retrnsmt >> uid_str >> timeout >> inode_str;

        SocketEntry e;
        auto colon1 = local.find(':');
        auto colon2 = remote.find(':');
        if (colon1 == std::string::npos || colon2 == std::string::npos) continue;

        e.local_addr  = hex_to_ip(local.substr(0, colon1));
        e.local_port  = hex_to_port(local.substr(colon1 + 1));
        e.remote_addr = hex_to_ip(remote.substr(0, colon2));
        e.remote_port = hex_to_port(remote.substr(colon2 + 1));
        e.state       = static_cast<int>(std::stoul(state_str, nullptr, 16));
        e.uid         = std::stoi(uid_str);
        try { e.inode = std::stoi(inode_str); } catch (...) { e.inode = 0; }

        entries.push_back(e);
    }
    return entries;
}

std::vector<NetworkCollector::ArpEntry> NetworkCollector::parse_proc_net_arp() {
    std::vector<ArpEntry> entries;
    std::ifstream f("/proc/net/arp");
    if (!f.is_open()) return entries;

    std::string line;
    std::getline(f, line); // Skip header

    while (std::getline(f, line)) {
        std::istringstream iss(line);
        ArpEntry e;
        std::string hw_type, flags, hw_addr;
        iss >> e.ip >> hw_type >> flags >> e.mac >> hw_addr >> e.device;
        if (!e.ip.empty()) entries.push_back(e);
    }
    return entries;
}

std::string NetworkCollector::resolve_pid_for_inode(int inode) {
    if (inode <= 0) return "";

    // Scan /proc/*/fd/* for matching socket inode
    std::string target = "socket:[" + std::to_string(inode) + "]";
    DIR* proc_dir = opendir("/proc");
    if (!proc_dir) return "";

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
            char link_buf[256];
            std::string fd_path = fd_dir + "/" + fd_entry->d_name;
            ssize_t len = readlink(fd_path.c_str(), link_buf, sizeof(link_buf) - 1);
            if (len > 0) {
                link_buf[len] = '\0';
                if (target == link_buf) {
                    closedir(fds);
                    std::string pid = entry->d_name;
                    closedir(proc_dir);
                    return pid;
                }
            }
        }
        closedir(fds);
    }
    closedir(proc_dir);
    return "";
}

void NetworkCollector::collect(const EventCallback& emit) {
    if (!enabled_) return;

    std::string ts = now_utc();

    // Check listening sockets
    auto tcp_entries = parse_proc_net_tcp("/proc/net/tcp");
    std::set<int> current_listening;

    for (const auto& entry : tcp_entries) {
        // TCP state 0x0A = LISTEN
        if (entry.state == 0x0A) {
            current_listening.insert(entry.local_port);

            // New listening port
            if (known_listening_ports_.find(entry.local_port) == known_listening_ports_.end()) {
                std::string pid = resolve_pid_for_inode(entry.inode);
                Severity sev = (entry.local_port > 1024 && entry.local_port < 10000)
                                ? Severity::Info : Severity::Medium;
                // High or random ports are suspicious
                if (entry.local_port > 49151) sev = Severity::High;

                nlohmann::json details = {
                    {"local_addr", entry.local_addr},
                    {"local_port", entry.local_port},
                    {"protocol", "tcp"},
                    {"pid", pid},
                    {"uid", entry.uid}
                };

                Event e;
                e.event_id       = UUID::generate();
                e.schema_version = SCHEMA_VERSION;
                e.event_type     = "network.port_listening";
                e.category       = Category::Network;
                e.timestamp      = ts;
                e.observed_at    = ts;
                e.actor          = pid.empty() ? "uid=" + std::to_string(entry.uid) : "pid=" + pid;
                e.severity       = sev;
                e.source         = "/proc/net/tcp";
                e.details        = details;
                e.collector_status = "ok";

                emit(e);
                status_.events_emitted++;
            }
        }

        // Outbound established connections
        if (entry.state == 0x01 && entry.remote_addr != "0.0.0.0" && entry.remote_addr != "127.0.0.1") {
            std::string pid = resolve_pid_for_inode(entry.inode);
            nlohmann::json details = {
                {"local_addr", entry.local_addr},
                {"local_port", entry.local_port},
                {"remote_addr", entry.remote_addr},
                {"remote_port", entry.remote_port},
                {"protocol", "tcp"},
                {"pid", pid},
                {"uid", entry.uid}
            };

            Event e;
            e.event_id       = UUID::generate();
            e.schema_version = SCHEMA_VERSION;
            e.event_type     = "network.outbound_connection";
            e.category       = Category::Network;
            e.timestamp      = ts;
            e.observed_at    = ts;
            e.actor          = pid.empty() ? "uid=" + std::to_string(entry.uid) : "pid=" + pid;
            e.severity       = Severity::Info;
            e.source         = "/proc/net/tcp";
            e.details        = details;
            e.collector_status = "ok";

            emit(e);
            status_.events_emitted++;
        }
    }

    known_listening_ports_ = current_listening;

    // Check ARP table changes
    auto arp_entries = parse_proc_net_arp();
    std::set<std::string> current_arp;

    for (const auto& arp : arp_entries) {
        std::string key = arp.ip + "|" + arp.mac;
        current_arp.insert(key);

        if (known_arp_entries_.find(key) == known_arp_entries_.end()) {
            nlohmann::json details = {
                {"ip", arp.ip},
                {"mac", arp.mac},
                {"device", arp.device}
            };

            Event e;
            e.event_id       = UUID::generate();
            e.schema_version = SCHEMA_VERSION;
            e.event_type     = "network.arp_change";
            e.category       = Category::Network;
            e.timestamp      = ts;
            e.observed_at    = ts;
            e.actor          = "device=" + arp.device;
            e.severity       = Severity::Low;
            e.source         = "/proc/net/arp";
            e.details        = details;
            e.collector_status = "ok";

            emit(e);
            status_.events_emitted++;
        }
    }

    known_arp_entries_ = current_arp;
    status_.last_collect = ts;
    status_.accessible = true;
}

CollectorStatus NetworkCollector::status() const {
    return status_;
}

} // namespace skynet
