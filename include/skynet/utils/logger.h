#pragma once
// SkyNet — Structured Logger
// Thread-safe structured logging to stderr/file with severity levels.

#include <string>
#include <mutex>
#include <iostream>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace skynet {

enum class LogLevel { Debug, Info, Warn, Error };

class Logger {
public:
    static Logger& instance() {
        static Logger log;
        return log;
    }

    void set_level(LogLevel level) { level_ = level; }
    void set_file(const std::string& path) {
        std::lock_guard<std::mutex> lock(mtx_);
        if (file_.is_open()) file_.close();
        file_.open(path, std::ios::app);
    }

    void log(LogLevel level, const std::string& component, const std::string& msg) {
        if (level < level_) return;
        std::lock_guard<std::mutex> lock(mtx_);
        std::string line = format(level, component, msg);
        std::cerr << line << "\n";
        if (file_.is_open()) {
            file_ << line << "\n";
            file_.flush();
        }
    }

    void debug(const std::string& component, const std::string& msg) { log(LogLevel::Debug, component, msg); }
    void info (const std::string& component, const std::string& msg) { log(LogLevel::Info,  component, msg); }
    void warn (const std::string& component, const std::string& msg) { log(LogLevel::Warn,  component, msg); }
    void error(const std::string& component, const std::string& msg) { log(LogLevel::Error, component, msg); }

private:
    Logger() = default;
    LogLevel level_ = LogLevel::Info;
    std::mutex mtx_;
    std::ofstream file_;

    static std::string now_iso() {
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

    static std::string level_str(LogLevel l) {
        switch (l) {
            case LogLevel::Debug: return "DEBUG";
            case LogLevel::Info:  return "INFO";
            case LogLevel::Warn:  return "WARN";
            case LogLevel::Error: return "ERROR";
        }
        return "INFO";
    }

    std::string format(LogLevel level, const std::string& component, const std::string& msg) {
        return now_iso() + " [" + level_str(level) + "] [" + component + "] " + msg;
    }
};

// Convenience macros
#define LOG_DEBUG(comp, msg) skynet::Logger::instance().debug(comp, msg)
#define LOG_INFO(comp, msg)  skynet::Logger::instance().info(comp, msg)
#define LOG_WARN(comp, msg)  skynet::Logger::instance().warn(comp, msg)
#define LOG_ERROR(comp, msg) skynet::Logger::instance().error(comp, msg)

} // namespace skynet
