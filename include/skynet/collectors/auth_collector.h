#pragma once
// SkyNet — Auth Collector
// Monitors /var/log/auth.log for login attempts, sudo, user changes, etc.

#include "collector.h"
#include "../utils/file_watcher.h"
#include "../utils/redactor.h"
#include "../utils/uuid.h"

namespace skynet {

class AuthCollector : public Collector {
public:
    std::string name() const override { return "auth"; }
    bool enabled() const override { return enabled_; }
    bool init(const Config& config) override;
    void collect(const EventCallback& emit) override;
    CollectorStatus status() const override;

private:
    bool enabled_ = true;
    std::unique_ptr<FileWatcher> watcher_;
    Redactor redactor_;
    CollectorStatus status_{"auth"};

    void parse_line(const std::string& line, const EventCallback& emit);
    Event make_event(const std::string& event_type, Severity sev,
                     const std::string& actor, const nlohmann::json& details,
                     const std::string& timestamp);
};

} // namespace skynet
