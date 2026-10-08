// SkyNet — Main Entry Point
// CLI argument parsing, signal handling, agent startup and fixture replay.

#include "skynet/agent.h"
#include "skynet/config.h"
#include "skynet/deep_scan.h"
#include "skynet/utils/logger.h"
#include <iostream>
#include <csignal>
#include <fstream>

static skynet::Agent* g_agent = nullptr;

static void handle_signal(int signum) {
    LOG_INFO("main", "Caught signal " + std::to_string(signum) + ", stopping agent...");
    if (g_agent) {
        g_agent->stop();
    }
}

static void print_usage(const char* prog) {
    std::cout << "SkyNet Endpoint Security Agent v" << skynet::SCHEMA_VERSION << "\n"
              << "Usage: " << prog << " [options]\n\n"
              << "Options:\n"
              << "  -c, --config <path>     Path to configuration JSON file\n"
              << "  -f, --replay <path>     Replay events from JSONL fixture file\n"
              << "  -s, --deep-scan [file]  Perform deep inventory scan (apps, DBs, binaries)\n"
              << "      --scan-dir <path>   Target custom directory for deep binary scan\n"
              << "  -d, --debug             Enable verbose debug logging\n"
              << "  -v, --version           Print version and exit\n"
              << "  -h, --help              Print this help and exit\n\n"
              << "Examples:\n"
              << "  " << prog << " --config config/skynet.json\n"
              << "  " << prog << " --replay fixtures/events.jsonl\n"
              << "  " << prog << " --deep-scan report.json\n";
}


static int run_replay(const std::string& fixture_path, const skynet::Config& base_config) {
    LOG_INFO("replay", "Running in fixture replay mode: " + fixture_path);

    std::ifstream file(fixture_path);
    if (!file.is_open()) {
        LOG_ERROR("replay", "Could not open fixture file: " + fixture_path);
        return 1;
    }

    skynet::Correlator correlator;
    skynet::Enricher enricher;
    enricher.init(base_config);

    std::vector<skynet::Alert> alerts;
    int event_count = 0;
    std::string line;

    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        try {
            auto j = nlohmann::json::parse(line);
            skynet::Event ev;
            skynet::from_json(j, ev);
            enricher.enrich(ev);
            event_count++;

            correlator.process(ev, [&](skynet::Alert a) {
                alerts.push_back(a);
                LOG_WARN("replay", "--> ALERT TRIGGERED: [" + a.rule_id + "] " + a.explanation);
            });
        } catch (const std::exception& e) {
            LOG_ERROR("replay", "Error parsing event line: " + std::string(e.what()));
        }
    }

    std::cout << "\n=== Replay Summary ===\n";
    std::cout << "Events processed: " << event_count << "\n";
    std::cout << "Alerts triggered: " << alerts.size() << "\n";
    for (size_t i = 0; i < alerts.size(); ++i) {
        std::cout << "  [" << (i + 1) << "] Rule: " << alerts[i].rule_id
                  << " | Severity: " << severity_to_string(alerts[i].severity)
                  << " | Explanation: " << alerts[i].explanation << "\n";
    }

    return 0;
}

int main(int argc, char* argv[]) {
    std::string config_path = "config/skynet.json";
    std::string replay_path;
    std::string deep_scan_output;
    std::string scan_dir;
    bool run_deep_scan = false;
    bool debug = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-c" || arg == "--config") {
            if (i + 1 < argc) config_path = argv[++i];
        } else if (arg == "-f" || arg == "--replay") {
            if (i + 1 < argc) replay_path = argv[++i];
        } else if (arg == "-s" || arg == "--deep-scan") {
            run_deep_scan = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                deep_scan_output = argv[++i];
            }
        } else if (arg == "--scan-dir") {
            if (i + 1 < argc) scan_dir = argv[++i];
        } else if (arg == "-d" || arg == "--debug") {
            debug = true;
        } else if (arg == "-v" || arg == "--version") {
            std::cout << "SkyNet Agent v" << skynet::SCHEMA_VERSION << "\n";
            return 0;
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    if (debug) {
        skynet::Logger::instance().set_level(skynet::LogLevel::Debug);
    }

    if (run_deep_scan) {
        LOG_INFO("main", "Starting deep system inventory scan...");
        skynet::DeepScanner scanner;
        auto report = scanner.run_scan(scan_dir);
        scanner.print_summary(report);

        if (!deep_scan_output.empty()) {
            if (scanner.save_report(report, deep_scan_output)) {
                std::cout << "\nDeep scan report saved to: " << deep_scan_output << "\n";
            } else {
                std::cerr << "\nFailed to write report to: " << deep_scan_output << "\n";
                return 1;
            }
        }
        return 0;
    }

    skynet::Config config = skynet::Config::load(config_path);
    if (debug) config.debug_mode = true;

    if (!replay_path.empty()) {
        return run_replay(replay_path, config);
    }


    // Set up signal handling
    std::signal(SIGINT,  handle_signal);
    std::signal(SIGTERM, handle_signal);

    skynet::Agent agent;
    g_agent = &agent;

    if (!agent.init(config)) {
        LOG_ERROR("main", "Agent initialization failed.");
        return 1;
    }

    agent.run();
    g_agent = nullptr;
    return 0;
}
