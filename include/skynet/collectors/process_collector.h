#pragma once
// SkyNet — Process Collector
// Scans /proc to monitor running processes, command lines, CPU/memory.

#include "collector.h"
#include "../utils/redactor.h"
#include "../utils/uuid.h"
#include <set>

namespace skynet {

class ProcessCollector : public Collector {
public:
    std::string name() const override { return "process"; }
    bool enabled() const override { return enabled_; }
    bool init(const Config& config) override;
    void collect(const EventCallback& emit) override;
    CollectorStatus status() const override;

private:
    bool enabled_ = true;
    Redactor redactor_;
    CollectorStatus status_{"process"};

    // Track known PIDs to detect new/stopped processes
    std::set<int> known_pids_;

    struct ProcInfo {
        int pid;
        int ppid;
        std::string comm;
        std::string exe;
        std::string cmdline;
        std::string user;
        unsigned long utime;
        unsigned long stime;
        long rss;       // resident set size in pages
        char state;
    };

    std::vector<ProcInfo> scan_proc();
    ProcInfo read_proc_entry(int pid);
    std::string get_proc_user(int pid);
    bool is_suspicious_path(const std::string& exe);
    bool is_high_resource(const ProcInfo& info);
};

} // namespace skynet
