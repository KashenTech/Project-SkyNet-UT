#pragma once
// SkyNet — Base Collector Interface
// All collectors implement this interface for the agent pipeline.

#include <string>
#include <vector>
#include <functional>
#include "../types.h"
#include "../config.h"

namespace skynet {

/// Callback type: collector pushes events through this.
using EventCallback = std::function<void(Event)>;

/// Abstract base for all telemetry collectors.
class Collector {
public:
    virtual ~Collector() = default;

    /// Human-readable name ("auth", "process", "network", etc.)
    virtual std::string name() const = 0;

    /// Initialize the collector. Returns false if critical resources missing.
    virtual bool init(const Config& config) = 0;

    /// Perform one collection cycle. Push events via the callback.
    virtual void collect(const EventCallback& emit) = 0;

    /// Get current status for health reporting.
    virtual CollectorStatus status() const = 0;

    /// Whether this collector is enabled in config.
    virtual bool enabled() const = 0;
};

} // namespace skynet
