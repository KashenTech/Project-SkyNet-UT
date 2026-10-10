#pragma once
// SkyNet — Network Collector
// Monitors listening ports, outbound connections, ARP table, DNS.

#include "collector.h"
#include "../utils/uuid.h"
#include <set>

namespace skynet {

class NetworkCollector : public Collector {
public:
    std::string name() const override { return "network"; }
    bool enabled() const override { return enabled_; }
    bool init(const Config& config) override;
    void collect(const EventCallback& emit) override;
    CollectorStatus status() const override;

private:
    bool enabled_ = true;
    CollectorStatus status_{"network"};

    struct SocketEntry {
        std::string local_addr;
        int         local_port;
        std::string remote_addr;
        int         remote_port;
        int         state;  // TCP state
        int         inode;
        int         uid;
    };

    struct ArpEntry {
        std::string ip;
        std::string mac;
        std::string device;
    };

    // Baseline tracking
    std::set<int> known_listening_ports_;
    std::set<std::string> known_arp_entries_; // "ip|mac"

    std::vector<SocketEntry> parse_proc_net_tcp(const std::string& path);
    std::vector<ArpEntry> parse_proc_net_arp();
    std::string resolve_pid_for_inode(int inode);
    std::string hex_to_ip(const std::string& hex);
    int hex_to_port(const std::string& hex);
};

} // namespace skynet
