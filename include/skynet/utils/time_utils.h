#pragma once
// SkyNet — Time Utilities
// Cross-platform ISO-8601 UTC timestamp helper.

#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>

namespace skynet {

inline std::string now_utc() {
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

} // namespace skynet
