#include "skynet/deep_scan.h"
#include <cassert>
#include <iostream>
#include <sstream>
#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

int main() {
    std::cout << "Running DeepScanner tests...\n";

    skynet::DeepScanner scanner;

    // Run deep scan on current working directory as custom target
    auto report = scanner.run_scan(fs::current_path().string());

    assert(!report.timestamp.empty());
    assert(!report.hostname.empty());

    // Verify JSON serialization
    nlohmann::json j = scanner.to_json(report);
    assert(j.contains("timestamp"));
    assert(j.contains("hostname"));
    assert(j.contains("summary"));
    assert(j["summary"].contains("total_packages"));
    assert(j["summary"].contains("total_applications"));
    assert(j["summary"].contains("total_binaries"));
    assert(j["summary"].contains("total_services"));
    assert(j.contains("detected_databases"));
    assert(j.contains("privileged_binaries"));

    // Verify summary output printing to stream
    std::ostringstream ss;
    scanner.print_summary(report, ss);
    std::string summary_str = ss.str();
    assert(summary_str.find("SkyNet Deep System Inventory") != std::string::npos);
    assert(summary_str.find("Timestamp:") != std::string::npos);

    // Verify saving report to file
    std::string test_output = "test_deep_scan_output.json";
    bool saved = scanner.save_report(report, test_output);
    assert(saved);
    assert(fs::exists(test_output));

    // Verify file content is valid JSON
    std::ifstream in(test_output);
    nlohmann::json file_j;
    in >> file_j;
    assert(file_j["timestamp"] == report.timestamp);
    in.close();
    fs::remove(test_output);

    std::cout << "All DeepScanner tests passed successfully!\n";
    return 0;
}
