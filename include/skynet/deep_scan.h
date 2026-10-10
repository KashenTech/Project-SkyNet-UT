#pragma once

#include <string>
#include <vector>
#include <iostream>
#include "../../third_party/nlohmann/json.hpp"

namespace skynet {

struct DeepScanReport {
    std::string timestamp;
    std::string hostname;
    int total_packages = 0;
    int total_applications = 0;
    int total_binaries = 0;
    int total_services = 0;
    std::vector<std::string> detected_databases;
    std::vector<nlohmann::json> privileged_binaries; // SUID/SGID executable binaries
    std::vector<nlohmann::json> desktop_applications; // Installed GUI/desktop tools (.desktop)
    std::vector<nlohmann::json> system_services;      // Background services & daemons
    std::vector<nlohmann::json> installed_packages;   // OS package manager inventory
};

class DeepScanner {
public:
    /// Run a comprehensive deep scan across packages, apps, databases, and binaries.
    /// If custom_target_dir is provided, scans that directory for executables and binaries.
    DeepScanReport run_scan(const std::string& custom_target_dir = "");

    /// Convert report to canonical JSON format.
    nlohmann::json to_json(const DeepScanReport& report) const;

    /// Print a human-readable executive summary to standard output or a stream.
    void print_summary(const DeepScanReport& report, std::ostream& out = std::cout) const;

    /// Save full JSON report to file.
    bool save_report(const DeepScanReport& report, const std::string& output_path) const;

private:
    void scan_packages(DeepScanReport& report);
    void scan_desktop_applications(DeepScanReport& report);
    void scan_databases(DeepScanReport& report);
    void scan_services(DeepScanReport& report);
    void scan_binaries(DeepScanReport& report, const std::string& custom_dir);
};

} // namespace skynet
