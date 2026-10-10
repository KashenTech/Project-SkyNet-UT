#pragma once
// SkyNet — UUID Generator
// Generates v4-style UUIDs using /proc/sys/kernel/random/uuid or fallback.

#include <string>
#include <fstream>
#include <random>
#include <sstream>
#include <iomanip>

namespace skynet {

class UUID {
public:
    /// Generate a UUID. Tries Linux kernel source first, then falls back to random.
    static std::string generate() {
        // Try Linux kernel UUID source
        std::ifstream f("/proc/sys/kernel/random/uuid");
        if (f.is_open()) {
            std::string uuid;
            std::getline(f, uuid);
            if (!uuid.empty()) return uuid;
        }
        // Fallback: pseudo-random v4 UUID
        return generate_random();
    }

private:
    static std::string generate_random() {
        static thread_local std::mt19937_64 rng(std::random_device{}());
        std::uniform_int_distribution<uint64_t> dist;

        uint64_t a = dist(rng);
        uint64_t b = dist(rng);

        // Set version 4 and variant bits
        a = (a & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;
        b = (b & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;

        auto hex = [](uint64_t val, int bytes) {
            std::ostringstream ss;
            ss << std::hex << std::setfill('0') << std::setw(bytes * 2) << val;
            return ss.str();
        };

        std::ostringstream uuid;
        uuid << hex((a >> 32) & 0xFFFFFFFF, 4) << "-"
             << hex((a >> 16) & 0xFFFF, 2) << "-"
             << hex(a & 0xFFFF, 2) << "-"
             << hex((b >> 48) & 0xFFFF, 2) << "-"
             << hex(b & 0xFFFFFFFFFFFFULL, 6);
        return uuid.str();
    }
};

} // namespace skynet
