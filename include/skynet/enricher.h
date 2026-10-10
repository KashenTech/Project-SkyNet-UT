#pragma once
// SkyNet — Context Enricher
// Attaches host, user, process tree, baseline, and confidence to events.

#include "types.h"
#include "config.h"
#include <string>

namespace skynet {

class Enricher {
public:
    void init(const Config& config);

    /// Enrich an event with host context, process tree, baseline info.
    void enrich(Event& event);

    /// Get current host info.
    const HostInfo& host_info() const { return host_info_; }

private:
    HostInfo host_info_;
    Config config_;

    void discover_host();
    std::string read_file_line(const std::string& path);
};

} // namespace skynet
