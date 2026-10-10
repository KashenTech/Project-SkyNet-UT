#pragma once
// SkyNet — Sensitive Data Redactor
// Redacts passwords, tokens, keys, and other sensitive values from strings.

#include <string>
#include <regex>
#include <vector>
#include <functional>

namespace skynet {

class Redactor {
public:
    Redactor() {
        // Password patterns in logs and command lines
        patterns_.emplace_back(
            std::regex(R"((password|passwd|pass|pwd)\s*[=:]\s*\S+)", std::regex::icase),
            "$1=<REDACTED>"
        );
        // Token/key patterns
        patterns_.emplace_back(
            std::regex(R"((token|api_key|apikey|secret)\s*[=:]\s*\S+)", std::regex::icase),
            "$1=<REDACTED>"
        );
        // Bearer tokens in Authorization headers
        patterns_.emplace_back(
            std::regex(R"((bearer)\s+[A-Za-z0-9._\-~+/=]+)", std::regex::icase),
            "$1 <REDACTED>"
        );
        // SSH private key content
        patterns_.emplace_back(
            std::regex(R"(-----BEGIN\s+\w+\s+PRIVATE\s+KEY-----[\s\S]*?-----END\s+\w+\s+PRIVATE\s+KEY-----)"),
            "<REDACTED_PRIVATE_KEY>"
        );
        // Base64-encoded long strings in command lines (potential encoded payloads)
        patterns_.emplace_back(
            std::regex(R"((?:echo|base64|eval)\s+[A-Za-z0-9+/=]{64,})"),
            "<REDACTED_ENCODED_DATA>"
        );
        // Email addresses
        patterns_.emplace_back(
            std::regex(R"(\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b)"),
            "<REDACTED_EMAIL>"
        );
    }

    /// Redact sensitive patterns from a string.
    std::string redact(const std::string& input) const {
        std::string result = input;
        for (const auto& [pattern, replacement] : patterns_) {
            result = std::regex_replace(result, pattern, replacement);
        }
        return result;
    }

    /// Redact command-line arguments that look like secrets.
    std::string redact_cmdline(const std::string& cmdline) const {
        return redact(cmdline);
    }

    /// Hash a value for correlation without exposing the original (simple djb2).
    static std::string hash_value(const std::string& value) {
        unsigned long hash = 5381;
        for (char c : value) {
            hash = ((hash << 5) + hash) + static_cast<unsigned char>(c);
        }
        char buf[20];
        snprintf(buf, sizeof(buf), "hash:%lx", hash);
        return std::string(buf);
    }

private:
    std::vector<std::pair<std::regex, std::string>> patterns_;
};

} // namespace skynet
