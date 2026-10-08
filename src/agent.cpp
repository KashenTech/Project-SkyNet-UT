// SkyNet — Agent Orchestrator Implementation
// Manages collector lifecycles, runs the collection loop, and handles pipeline dispatch.

#include "skynet/agent.h"
#include "skynet/collectors/auth_collector.h"
#include "skynet/collectors/process_collector.h"
#include "skynet/collectors/network_collector.h"
#include "skynet/collectors/file_collector.h"
#include "skynet/collectors/usb_collector.h"
#include "skynet/collectors/system_collector.h"
#include "skynet/collectors/app_collector.h"
#include "skynet/utils/logger.h"
#include "skynet/utils/uuid.h"
#include <chrono>
#include <thread>
#include <iomanip>
#include <sstream>

namespace skynet {

static std::string now_utc() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

bool Agent::init(const Config& config) {
    config_ = config;

    if (config_.debug_mode) {
        Logger::instance().set_level(LogLevel::Debug);
    }
    if (!config_.log_file.empty()) {
        Logger::instance().set_file(config_.log_file);
    }

    LOG_INFO("agent", "Initializing SkyNet Agent v" + std::string(SCHEMA_VERSION) + "...");

    // Validate config
    auto errors = config_.validate();
    for (const auto& err : errors) {
        LOG_WARN("config", "Validation warning: " + err);
    }

    // Initialize pipeline components
    enricher_.init(config_);
    queue_.init(config_);
    transport_.init(config_);

    // Register active collectors
    register_collectors();

    LOG_INFO("agent", "Initialization complete. Registered " +
             std::to_string(collectors_.size()) + " collectors.");
    return true;
}

void Agent::register_collectors() {
    collectors_.clear();

    if (config_.enable_auth) {
        auto c = std::make_unique<AuthCollector>();
        if (c->init(config_)) {
            collectors_.push_back(std::move(c));
        } else {
            LOG_WARN("agent", "AuthCollector failed init, disabled");
        }
    }

    if (config_.enable_process) {
        auto c = std::make_unique<ProcessCollector>();
        if (c->init(config_)) {
            collectors_.push_back(std::move(c));
        } else {
            LOG_WARN("agent", "ProcessCollector failed init, disabled");
        }
    }

    if (config_.enable_network) {
        auto c = std::make_unique<NetworkCollector>();
        if (c->init(config_)) {
            collectors_.push_back(std::move(c));
        } else {
            LOG_WARN("agent", "NetworkCollector failed init, disabled");
        }
    }

    if (config_.enable_file) {
        auto c = std::make_unique<FileCollector>();
        if (c->init(config_)) {
            collectors_.push_back(std::move(c));
        } else {
            LOG_WARN("agent", "FileCollector failed init, disabled");
        }
    }

    if (config_.enable_usb) {
        auto c = std::make_unique<USBCollector>();
        if (c->init(config_)) {
            collectors_.push_back(std::move(c));
        } else {
            LOG_WARN("agent", "USBCollector failed init, disabled");
        }
    }

    if (config_.enable_system) {
        auto c = std::make_unique<SystemCollector>();
        if (c->init(config_)) {
            collectors_.push_back(std::move(c));
        } else {
            LOG_WARN("agent", "SystemCollector failed init, disabled");
        }
    }

    if (config_.enable_app) {
        auto c = std::make_unique<AppCollector>();
        if (c->init(config_)) {
            collectors_.push_back(std::move(c));
        } else {
            LOG_WARN("agent", "AppCollector failed init, disabled");
        }
    }
}

void Agent::emit_lifecycle_event(const std::string& event_type) {
    Event e;
    e.event_id         = UUID::generate();
    e.schema_version   = SCHEMA_VERSION;
    e.event_type       = event_type;
    e.category         = Category::Agent;
    e.timestamp        = now_utc();
    e.observed_at      = e.timestamp;
    e.host_id          = enricher_.host_info().host_id;
    e.hostname         = enricher_.host_info().hostname;
    e.actor            = "skynet-agent";
    e.severity         = Severity::Info;
    e.source           = "agent";
    e.collector_status = "ok";
    e.details          = {
        {"agent_version", enricher_.host_info().agent_version},
        {"config", config_.to_json()}
    };

    on_event(std::move(e));
}

void Agent::on_event(Event event) {
    // 1. Enrich
    enricher_.enrich(event);

    // 2. Correlate
    correlator_.process(event, [this](Alert alert) {
        on_alert(std::move(alert));
    });

    // 3. Queue
    queue_.push(event);
}

void Agent::on_alert(Alert alert) {
    LOG_WARN("correlator", "ALERT TRIGGERED: [" + alert.rule_id + "] " + alert.explanation);
    queue_.push_alert(alert);
}

void Agent::collection_cycle() {
    auto now = Clock::now();

    for (auto& col : collectors_) {
        if (!col->enabled()) continue;

        int interval = 10;
        const auto& name = col->name();
        if (name == "auth")       interval = config_.poll_interval_auth;
        else if (name == "process") interval = config_.poll_interval_process;
        else if (name == "network") interval = config_.poll_interval_network;
        else if (name == "file")    interval = config_.poll_interval_file;
        else if (name == "usb")     interval = config_.poll_interval_usb;
        else if (name == "system")  interval = config_.poll_interval_system;
        else if (name == "app")     interval = config_.poll_interval_app;

        auto last = last_collect_[name];
        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last).count();

        // Run on first tick (last == epoch) or when elapsed >= interval
        if (last == Clock::time_point{} || elapsed >= interval) {
            try {
                col->collect([this](Event e) {
                    on_event(std::move(e));
                });
            } catch (const std::exception& ex) {
                LOG_ERROR("agent", "Collector exception in " + name + ": " + ex.what());
            }
            last_collect_[name] = now;
        }
    }
}

void Agent::flush_cycle() {
    // Drain and send alerts first
    std::vector<Alert> alerts;
    int alert_count = queue_.drain_alerts(alerts);
    if (alert_count > 0) {
        transport_.send_alerts(alerts);
    }

    // Drain and send events in batches
    std::vector<Event> batch;
    while (true) {
        int drained = queue_.drain_events(batch, config_.batch_size);
        if (drained <= 0) break;
        transport_.send_events(batch);
        batch.clear();
    }
}

void Agent::run() {
    running_ = true;

    // Send initial host info snapshot
    transport_.send_host_info(enricher_.host_info());

    // Emit startup event
    emit_lifecycle_event("agent.started");
    LOG_INFO("agent", "SkyNet Agent running. Host: " + enricher_.host_info().hostname);

    auto last_flush = Clock::now();

    while (running_) {
        collection_cycle();

        auto now = Clock::now();
        auto flush_elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_flush).count();
        if (flush_elapsed >= config_.flush_interval ||
            static_cast<int>(queue_.event_count()) >= config_.batch_size) {
            flush_cycle();
            last_flush = now;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    LOG_INFO("agent", "SkyNet Agent shutting down...");
    emit_lifecycle_event("agent.stopped");

    // Final flush
    flush_cycle();

    // Persist any unwritten to spool
    queue_.flush_to_spool();

    LOG_INFO("agent", "Agent shutdown complete.");
}

void Agent::stop() {
    running_ = false;
}

HostInfo Agent::host_info() const {
    return enricher_.host_info();
}

} // namespace skynet
