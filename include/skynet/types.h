#pragma once
// SkyNet Endpoint Agent — Core Types
// Canonical event schema, alert, and host metadata structures.

#include <string>
#include <vector>
#include <chrono>
#include <cstdint>
#include "../../third_party/nlohmann/json.hpp"

namespace skynet {

// Schema version
constexpr const char* SCHEMA_VERSION = "1.0.0";

enum class Severity {
    Info,
    Low,
    Medium,
    High,
    Critical
};

enum class Category {
    Auth,
    Process,
    File,
    Network,
    System,
    USB,
    Application,
    Error,
    Agent    // internal lifecycle events (started/stopped)
};

// Canonical event structure
struct Event {
    std::string event_id;            // Unique UUID
    std::string schema_version;      // e.g. "1.0.0"
    std::string event_type;          // e.g. "auth.login_failed"
    Category    category;
    std::string timestamp;           // ISO-8601 UTC
    std::string observed_at;         // When collector saw it
    std::string host_id;             // Stable host identity
    std::string hostname;
    std::string actor;               // uid, pid, user, remote IP
    Severity    severity;
    std::string source;              // File/tool that produced it
    nlohmann::json details;          // Category-specific fields
    std::vector<std::string> related_event_ids;
    std::string collector_status;    // "ok", "partial", "error"
};

// Correlation alert
struct Alert {
    std::string alert_id;
    std::string rule_id;             // e.g. "brute_force_success"
    Severity    severity;
    double      confidence;          // 0.0 – 1.0
    std::string explanation;
    std::string first_seen;          // ISO-8601
    std::string last_seen;           // ISO-8601
    std::vector<std::string> related_event_ids;
};

// Host metadata
struct HostInfo {
    std::string host_id;
    std::string hostname;
    std::string os;
    std::string os_version;
    std::string kernel;
    std::string agent_version;
    std::string started_at;
};

// Collector status
struct CollectorStatus {
    std::string name;
    bool        enabled       = true;
    bool        accessible    = false;
    std::string last_error;
    std::string last_collect;        // ISO-8601
    uint64_t    events_emitted = 0;
};

// JSON serialization helpers

inline std::string severity_to_string(Severity s) {
    switch (s) {
        case Severity::Info:     return "info";
        case Severity::Low:      return "low";
        case Severity::Medium:   return "medium";
        case Severity::High:     return "high";
        case Severity::Critical: return "critical";
    }
    return "info";
}

inline Severity severity_from_string(const std::string& s) {
    if (s == "low")      return Severity::Low;
    if (s == "medium")   return Severity::Medium;
    if (s == "high")     return Severity::High;
    if (s == "critical") return Severity::Critical;
    return Severity::Info;
}

inline std::string category_to_string(Category c) {
    switch (c) {
        case Category::Auth:        return "auth";
        case Category::Process:     return "process";
        case Category::File:        return "file";
        case Category::Network:     return "network";
        case Category::System:      return "system";
        case Category::USB:         return "usb";
        case Category::Application: return "application";
        case Category::Error:       return "error";
        case Category::Agent:       return "agent";
    }
    return "unknown";
}

inline Category category_from_string(const std::string& s) {
    if (s == "auth")        return Category::Auth;
    if (s == "process")     return Category::Process;
    if (s == "file")        return Category::File;
    if (s == "network")     return Category::Network;
    if (s == "system")      return Category::System;
    if (s == "usb")         return Category::USB;
    if (s == "application") return Category::Application;
    if (s == "error")       return Category::Error;
    if (s == "agent")       return Category::Agent;
    return Category::System;
}

inline void to_json(nlohmann::json& j, const Event& e) {
    j = nlohmann::json{
        {"event_id",          e.event_id},
        {"schema_version",    e.schema_version},
        {"event_type",        e.event_type},
        {"category",          category_to_string(e.category)},
        {"timestamp",         e.timestamp},
        {"observed_at",       e.observed_at},
        {"host_id",           e.host_id},
        {"hostname",          e.hostname},
        {"actor",             e.actor},
        {"severity",          severity_to_string(e.severity)},
        {"source",            e.source},
        {"details",           e.details},
        {"related_event_ids", e.related_event_ids},
        {"collector_status",  e.collector_status}
    };
}

inline void from_json(const nlohmann::json& j, Event& e) {
    j.at("event_id").get_to(e.event_id);
    j.at("schema_version").get_to(e.schema_version);
    j.at("event_type").get_to(e.event_type);
    e.category = category_from_string(j.at("category").get<std::string>());
    j.at("timestamp").get_to(e.timestamp);
    j.at("observed_at").get_to(e.observed_at);
    j.at("host_id").get_to(e.host_id);
    j.at("hostname").get_to(e.hostname);
    j.at("actor").get_to(e.actor);
    e.severity = severity_from_string(j.at("severity").get<std::string>());
    j.at("source").get_to(e.source);
    e.details = j.at("details");
    j.at("related_event_ids").get_to(e.related_event_ids);
    j.at("collector_status").get_to(e.collector_status);
}

inline void to_json(nlohmann::json& j, const Alert& a) {
    j = nlohmann::json{
        {"alert_id",          a.alert_id},
        {"rule_id",           a.rule_id},
        {"severity",          severity_to_string(a.severity)},
        {"confidence",        a.confidence},
        {"explanation",       a.explanation},
        {"first_seen",        a.first_seen},
        {"last_seen",         a.last_seen},
        {"related_event_ids", a.related_event_ids}
    };
}

inline void to_json(nlohmann::json& j, const HostInfo& h) {
    j = nlohmann::json{
        {"host_id",        h.host_id},
        {"hostname",       h.hostname},
        {"os",             h.os},
        {"os_version",     h.os_version},
        {"kernel",         h.kernel},
        {"agent_version",  h.agent_version},
        {"started_at",     h.started_at}
    };
}

} // namespace skynet
