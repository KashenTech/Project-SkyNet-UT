// SkyNet — Event Queue Implementation
// Bounded memory queue with disk spool for backend outage resilience.

#include "skynet/event_queue.h"
#include "skynet/utils/logger.h"
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <chrono>
#include <iomanip>
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

void EventQueue::init(const Config& config) {
    max_memory_ = config.queue_max_memory;
    spool_dir_  = config.spool_dir;
    spool_max_mb_ = config.spool_max_mb;

    // Create spool directory if it doesn't exist
    mkdir(spool_dir_.c_str(), 0700);

    // Load any existing spooled events
    load_from_spool();

    LOG_INFO("queue", "Event queue initialized (max_memory=" +
             std::to_string(max_memory_) + ", spool_dir=" + spool_dir_ + ")");
}

void EventQueue::push(const Event& event) {
    std::lock_guard<std::mutex> lock(event_mtx_);
    total_enqueued_++;

    if (static_cast<int>(events_.size()) >= max_memory_) {
        // Backpressure: spool to disk
        flush_to_spool();
    }

    events_.push(event);
}

void EventQueue::push_alert(const Alert& alert) {
    std::lock_guard<std::mutex> lock(alert_mtx_);
    alerts_.push(alert);
}

int EventQueue::drain_events(std::vector<Event>& out, int batch_size) {
    std::lock_guard<std::mutex> lock(event_mtx_);
    int count = 0;
    while (!events_.empty() && count < batch_size) {
        out.push_back(events_.front());
        events_.pop();
        count++;
    }
    return count;
}

int EventQueue::drain_alerts(std::vector<Alert>& out) {
    std::lock_guard<std::mutex> lock(alert_mtx_);
    int count = 0;
    while (!alerts_.empty()) {
        out.push_back(alerts_.front());
        alerts_.pop();
        count++;
    }
    return count;
}

size_t EventQueue::event_count() const {
    std::lock_guard<std::mutex> lock(event_mtx_);
    return events_.size();
}

size_t EventQueue::alert_count() const {
    std::lock_guard<std::mutex> lock(alert_mtx_);
    return alerts_.size();
}

void EventQueue::flush_to_spool() {
    // Write oldest events to disk to make room in memory
    std::string filename = spool_dir_ + "/spool_" + now_utc() + ".jsonl";
    // Replace colons in filename (invalid on some filesystems)
    for (char& c : filename) {
        if (c == ':') c = '-';
    }

    std::ofstream f(filename);
    if (!f.is_open()) {
        LOG_ERROR("queue", "Cannot write to spool file: " + filename);
        // Drop oldest events if we can't spool
        int dropped = 0;
        while (static_cast<int>(events_.size()) > max_memory_ / 2) {
            events_.pop();
            dropped++;
            total_dropped_++;
        }
        if (dropped > 0) {
            LOG_WARN("queue", "Dropped " + std::to_string(dropped) + " events (spool unavailable)");
        }
        return;
    }

    int spooled = 0;
    // Spool half the queue to disk
    int target = static_cast<int>(events_.size()) / 2;
    while (spooled < target && !events_.empty()) {
        nlohmann::json j = events_.front();
        f << j.dump() << "\n";
        events_.pop();
        spooled++;
        total_spooled_++;
    }

    f.close();
    LOG_INFO("queue", "Spooled " + std::to_string(spooled) + " events to " + filename);
}

void EventQueue::load_from_spool() {
    DIR* dir = opendir(spool_dir_.c_str());
    if (!dir) return;

    struct dirent* entry;
    int loaded = 0;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name.find("spool_") != 0) continue;

        std::string path = spool_dir_ + "/" + name;
        std::ifstream f(path);
        if (!f.is_open()) continue;

        std::string line;
        while (std::getline(f, line)) {
            if (line.empty()) continue;
            try {
                Event event = nlohmann::json::parse(line).get<Event>();
                events_.push(event);
                loaded++;
            } catch (const std::exception& e) {
                LOG_WARN("queue", "Failed to parse spooled event: " + std::string(e.what()));
            }
        }
        f.close();

        // Delete the spool file after loading
        unlink(path.c_str());
    }
    closedir(dir);

    if (loaded > 0) {
        LOG_INFO("queue", "Loaded " + std::to_string(loaded) + " events from spool");
    }
}

} // namespace skynet
