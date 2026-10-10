#pragma once

#include <string>
#include <vector>
#include <set>
#include <fstream>
#include <stdexcept>
#include "../../third_party/nlohmann/json.hpp"
#include "utils/logger.h"

namespace skynet {

struct Config {
    // Backend output
    std::string output_file    = "/var/lib/skynet/events.json";
    std::string alerts_file    = "/var/lib/skynet/alerts.json";
    int         batch_size     = 50;
    int         flush_interval = 10; // seconds

    // Host identity (detected if left empty)
    std::string host_id;
    std::string hostname;

    // Collector toggles
    bool enable_auth       = true;
    bool enable_process    = true;
    bool enable_network    = true;
    bool enable_file       = true;
    bool enable_usb        = true;
    bool enable_system     = true;
    bool enable_app        = true;

    // Polling intervals in seconds
    int poll_interval_auth    = 5;
    int poll_interval_process = 10;
    int poll_interval_network = 15;
    int poll_interval_file    = 10;
    int poll_interval_usb     = 5;
    int poll_interval_system  = 10;
    int poll_interval_app     = 15;

    // Watched paths
    std::string auth_log_path    = "/var/log/auth.log";
    std::string syslog_path      = "/var/log/syslog";
    std::string ufw_log_path     = "/var/log/ufw.log";
    std::string nginx_log_path   = "/var/log/nginx/access.log";
    std::string mysql_log_path   = "/var/log/mysql/error.log";
    std::vector<std::string> watch_paths = {"/etc", "/root", "/home"};

    // Queue and disk spool limits
    int         queue_max_memory = 10000; // max events held in memory
    std::string spool_dir        = "/var/lib/skynet/spool";
    int         spool_max_mb     = 100;

    // Logging & debug
    bool        debug_mode       = false;
    std::string log_file         = "/var/log/skynet/agent.log";

    // Fixture / replay mode
    bool        fixture_mode     = false;
    std::string fixture_file;

    static Config load(const std::string& path) {
        Config cfg;
        std::ifstream f(path);
        if (!f.is_open()) {
            LOG_WARN("config", "Config file not found at " + path + "; using defaults.");
            return cfg;
        }

        nlohmann::json j;
        try {
            f >> j;
        } catch (const std::exception& e) {
            throw std::runtime_error("Failed to parse config: " + std::string(e.what()));
        }

        auto get = [&](const char* key, auto& target) {
            if (j.contains(key)) j.at(key).get_to(target);
        };

        get("output_file",    cfg.output_file);
        get("alerts_file",    cfg.alerts_file);
        get("batch_size",     cfg.batch_size);
        get("flush_interval", cfg.flush_interval);
        get("host_id",        cfg.host_id);
        get("hostname",       cfg.hostname);

        get("enable_auth",    cfg.enable_auth);
        get("enable_process", cfg.enable_process);
        get("enable_network", cfg.enable_network);
        get("enable_file",    cfg.enable_file);
        get("enable_usb",     cfg.enable_usb);
        get("enable_system",  cfg.enable_system);
        get("enable_app",     cfg.enable_app);

        get("poll_interval_auth",    cfg.poll_interval_auth);
        get("poll_interval_process", cfg.poll_interval_process);
        get("poll_interval_network", cfg.poll_interval_network);
        get("poll_interval_file",    cfg.poll_interval_file);
        get("poll_interval_usb",     cfg.poll_interval_usb);
        get("poll_interval_system",  cfg.poll_interval_system);
        get("poll_interval_app",     cfg.poll_interval_app);

        get("auth_log_path",  cfg.auth_log_path);
        get("syslog_path",    cfg.syslog_path);
        get("ufw_log_path",   cfg.ufw_log_path);
        get("nginx_log_path", cfg.nginx_log_path);
        get("mysql_log_path", cfg.mysql_log_path);
        if (j.contains("watch_paths")) j.at("watch_paths").get_to(cfg.watch_paths);

        get("queue_max_memory", cfg.queue_max_memory);
        get("spool_dir",       cfg.spool_dir);
        get("spool_max_mb",    cfg.spool_max_mb);

        get("debug_mode",    cfg.debug_mode);
        get("log_file",      cfg.log_file);
        get("fixture_mode",  cfg.fixture_mode);
        get("fixture_file",  cfg.fixture_file);

        return cfg;
    }

    std::vector<std::string> validate() const {
        std::vector<std::string> errors;
        if (batch_size < 1 || batch_size > 10000)
            errors.push_back("batch_size must be 1-10000");
        if (flush_interval < 1 || flush_interval > 3600)
            errors.push_back("flush_interval must be 1-3600 seconds");
        if (poll_interval_auth < 1) errors.push_back("poll_interval_auth must be >= 1");
        if (poll_interval_process < 1) errors.push_back("poll_interval_process must be >= 1");
        if (poll_interval_network < 1) errors.push_back("poll_interval_network must be >= 1");
        if (queue_max_memory < 100) errors.push_back("queue_max_memory must be >= 100");
        if (output_file.empty()) errors.push_back("output_file must not be empty");
        return errors;
    }

    nlohmann::json to_json() const {
        return nlohmann::json{
            {"output_file", output_file},
            {"batch_size", batch_size},
            {"flush_interval", flush_interval},
            {"enable_auth", enable_auth},
            {"enable_process", enable_process},
            {"enable_network", enable_network},
            {"enable_file", enable_file},
            {"enable_usb", enable_usb},
            {"enable_system", enable_system},
            {"enable_app", enable_app},
            {"debug_mode", debug_mode},
            {"fixture_mode", fixture_mode}
        };
    }
};

} // namespace skynet
