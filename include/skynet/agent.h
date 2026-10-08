#pragma once
// SkyNet — Agent Orchestrator
// Main agent loop: initializes collectors, runs the pipeline, handles lifecycle.

#include "config.h"
#include "types.h"
#include "enricher.h"
#include "correlator.h"
#include "event_queue.h"
#include "transport.h"
#include "collectors/collector.h"
#include <vector>
#include <memory>
#include <atomic>
#include <thread>
#include <chrono>

namespace skynet {

class Agent {
public:
    /// Initialize the agent with the given configuration.
    bool init(const Config& config);

    /// Run the agent main loop (blocking). Call stop() from signal handler.
    void run();

    /// Signal the agent to shut down gracefully.
    void stop();

    /// Get host info for fixture output.
    HostInfo host_info() const;

private:
    Config config_;
    Enricher enricher_;
    Correlator correlator_;
    EventQueue queue_;
    Transport transport_;

    std::vector<std::unique_ptr<Collector>> collectors_;
    std::atomic<bool> running_{false};

    // Pipeline stages
    void register_collectors();
    void emit_lifecycle_event(const std::string& event_type);
    void collection_cycle();
    void flush_cycle();

    // Event pipeline callbacks
    void on_event(Event event);
    void on_alert(Alert alert);

    using Clock = std::chrono::steady_clock;
    std::map<std::string, Clock::time_point> last_collect_;
};

} // namespace skynet
