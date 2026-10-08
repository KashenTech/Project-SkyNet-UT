#pragma once
// SkyNet — Event Queue
// Bounded memory queue with disk spool fallback for backend outages.

#include "types.h"
#include "config.h"
#include <queue>
#include <mutex>
#include <string>
#include <atomic>

namespace skynet {

class EventQueue {
public:
    void init(const Config& config);

    /// Push an event into the queue.
    void push(const Event& event);

    /// Push an alert into the alert queue.
    void push_alert(const Alert& alert);

    /// Drain up to batch_size events into the output vector.
    /// Returns number of events drained.
    int drain_events(std::vector<Event>& out, int batch_size);

    /// Drain all pending alerts.
    int drain_alerts(std::vector<Alert>& out);

    /// Current queue sizes.
    size_t event_count() const;
    size_t alert_count() const;

    /// Flush to disk spool (called during shutdown or backpressure).
    void flush_to_spool();

    /// Load any spooled events back into memory.
    void load_from_spool();

    /// Backpressure metrics.
    uint64_t total_enqueued() const { return total_enqueued_; }
    uint64_t total_dropped()  const { return total_dropped_; }
    uint64_t total_spooled()  const { return total_spooled_; }

private:
    std::queue<Event> events_;
    std::queue<Alert> alerts_;
    mutable std::mutex event_mtx_;
    mutable std::mutex alert_mtx_;

    int max_memory_ = 10000;
    std::string spool_dir_;
    int spool_max_mb_ = 100;

    std::atomic<uint64_t> total_enqueued_{0};
    std::atomic<uint64_t> total_dropped_{0};
    std::atomic<uint64_t> total_spooled_{0};
};

} // namespace skynet
