// SkyNet — Process Collector Implementation
// Scans /proc filesystem for process lifecycle, command lines, resource usage.

#include "skynet/collectors/process_collector.h"
#include "skynet/utils/logger.h"
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <unistd.h>
#include <sys/stat.h>
#include <pwd.h>
#include <algorithm>
#include <cstring>

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

bool ProcessCollector::init(const Config& config) {
    enabled_ = config.enable_process;
    if (!enabled_) return true;

    status_.enabled = true;
    // Check /proc accessibility
    struct stat st{};
    status_.accessible = (stat("/proc", &st) == 0);
    if (!status_.accessible) {
        status_.last_error = "/proc not accessible";
        LOG_WARN("process", status_.last_error);
    }
    return true;
}

std::string ProcessCollector::get_proc_user(int pid) {
    struct stat st{};
    std::string path = "/proc/" + std::to_string(pid);
    if (stat(path.c_str(), &st) != 0) return "unknown";

    struct passwd* pw = getpwuid(st.st_uid);
    if (pw) return pw->pw_name;
    return "uid=" + std::to_string(st.st_uid);
}

ProcessCollector::ProcInfo ProcessCollector::read_proc_entry(int pid) {
    ProcInfo info{};
    info.pid = pid;

    // Read /proc/<pid>/stat
    std::string stat_path = "/proc/" + std::to_string(pid) + "/stat";
    std::ifstream stat_file(stat_path);
    if (stat_file.is_open()) {
        std::string stat_line;
        std::getline(stat_file, stat_line);

        // Parse past the comm field (which may contain spaces and parens)
        auto close_paren = stat_line.rfind(')');
        if (close_paren != std::string::npos) {
            // Extract comm
            auto open_paren = stat_line.find('(');
            if (open_paren != std::string::npos) {
                info.comm = stat_line.substr(open_paren + 1, close_paren - open_paren - 1);
            }
            // Fields after the closing paren
            std::istringstream rest(stat_line.substr(close_paren + 2));
            rest >> info.state;      // field 3: state
            rest >> info.ppid;       // field 4: ppid
            // Skip to fields 14, 15 (utime, stime) and field 24 (rss)
            std::string skip;
            for (int i = 0; i < 9; ++i) rest >> skip; // fields 5-13
            rest >> info.utime;      // field 14
            rest >> info.stime;      // field 15
            for (int i = 0; i < 8; ++i) rest >> skip; // fields 16-23
            rest >> info.rss;        // field 24
        }
    }

    // Read /proc/<pid>/exe (symlink to executable)
    char exe_buf[PATH_MAX];
    std::string exe_path = "/proc/" + std::to_string(pid) + "/exe";
    ssize_t len = readlink(exe_path.c_str(), exe_buf, sizeof(exe_buf) - 1);
    if (len > 0) {
        exe_buf[len] = '\0';
        info.exe = exe_buf;
    }

    // Read /proc/<pid>/cmdline
    std::string cmd_path = "/proc/" + std::to_string(pid) + "/cmdline";
    std::ifstream cmd_file(cmd_path);
    if (cmd_file.is_open()) {
        std::string cmdline;
        std::getline(cmd_file, cmdline, '\0');
        // Replace null bytes with spaces
        std::string full;
        std::getline(std::ifstream(cmd_path), full);
        std::replace(full.begin(), full.end(), '\0', ' ');
        info.cmdline = redactor_.redact_cmdline(full);
    }

    info.user = get_proc_user(pid);
    return info;
}

std::vector<ProcessCollector::ProcInfo> ProcessCollector::scan_proc() {
    std::vector<ProcInfo> procs;
    DIR* dir = opendir("/proc");
    if (!dir) return procs;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        // Only numeric directories (PIDs)
        if (entry->d_type != DT_DIR) continue;
        bool is_pid = true;
        for (const char* c = entry->d_name; *c; ++c) {
            if (!isdigit(*c)) { is_pid = false; break; }
        }
        if (!is_pid) continue;

        int pid = atoi(entry->d_name);
        if (pid <= 0) continue;

        try {
            procs.push_back(read_proc_entry(pid));
        } catch (...) {
            // Process may have exited between readdir and read
        }
    }
    closedir(dir);
    return procs;
}

bool ProcessCollector::is_suspicious_path(const std::string& exe) {
    // Programs running from /tmp, /dev/shm, /var/tmp, or /media, /mnt are suspicious
    static const std::vector<std::string> suspicious = {
        "/tmp/", "/dev/shm/", "/var/tmp/", "/media/", "/mnt/"
    };
    for (const auto& prefix : suspicious) {
        if (exe.find(prefix) == 0) return true;
    }
    return false;
}

bool ProcessCollector::is_high_resource(const ProcInfo& info) {
    // RSS > 1GB or very high CPU time
    long page_size = sysconf(_SC_PAGESIZE);
    long rss_bytes = info.rss * page_size;
    return rss_bytes > 1073741824L; // 1GB
}

void ProcessCollector::collect(const EventCallback& emit) {
    if (!enabled_) return;

    auto procs = scan_proc();
    std::set<int> current_pids;
    std::string ts = now_utc();

    for (const auto& proc : procs) {
        current_pids.insert(proc.pid);

        // New process detected
        if (known_pids_.find(proc.pid) == known_pids_.end()) {
            Severity sev = Severity::Info;
            if (is_suspicious_path(proc.exe)) sev = Severity::High;
            else if (is_high_resource(proc)) sev = Severity::Medium;

            nlohmann::json details = {
                {"pid", proc.pid},
                {"ppid", proc.ppid},
                {"comm", proc.comm},
                {"exe", proc.exe},
                {"cmdline", proc.cmdline},
                {"user", proc.user},
                {"state", std::string(1, proc.state)},
                {"rss_pages", proc.rss}
            };

            Event e;
            e.event_id       = UUID::generate();
            e.schema_version = SCHEMA_VERSION;
            e.event_type     = "process.started";
            e.category       = Category::Process;
            e.timestamp      = ts;
            e.observed_at    = ts;
            e.actor          = "pid=" + std::to_string(proc.pid) + " user=" + proc.user;
            e.severity       = sev;
            e.source         = "/proc";
            e.details        = details;
            e.collector_status = "ok";

            emit(e);
            status_.events_emitted++;
        }
    }

    // Detect stopped processes
    for (int pid : known_pids_) {
        if (current_pids.find(pid) == current_pids.end()) {
            nlohmann::json details = {{"pid", pid}};

            Event e;
            e.event_id       = UUID::generate();
            e.schema_version = SCHEMA_VERSION;
            e.event_type     = "process.stopped";
            e.category       = Category::Process;
            e.timestamp      = ts;
            e.observed_at    = ts;
            e.actor          = "pid=" + std::to_string(pid);
            e.severity       = Severity::Info;
            e.source         = "/proc";
            e.details        = details;
            e.collector_status = "ok";

            emit(e);
            status_.events_emitted++;
        }
    }

    known_pids_ = current_pids;
    status_.last_collect = ts;
    status_.accessible = true;
}

CollectorStatus ProcessCollector::status() const {
    return status_;
}

} // namespace skynet
