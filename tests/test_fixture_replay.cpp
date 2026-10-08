// SkyNet Tests — Fixture Replay Verification Test

#include "skynet/correlator.h"
#include <iostream>
#include <fstream>
#include <cassert>
#include <set>

int main() {
    std::cout << "=== SkyNet Fixture Replay Test ===\n";

    std::string fixture_file = "fixtures/events.jsonl";
    std::ifstream file(fixture_file);
    if (!file.is_open()) {
        fixture_file = "../fixtures/events.jsonl";
        file.open(fixture_file);
    }
    if (!file.is_open()) {
        std::cerr << "Failed to open fixtures/events.jsonl (checked both . and ..)\n";
        return 1;
    }

    skynet::Correlator correlator;
    std::vector<skynet::Alert> alerts;

    std::string line;
    int event_count = 0;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        auto j = nlohmann::json::parse(line);
        skynet::Event ev;
        skynet::from_json(j, ev);
        event_count++;

        correlator.process(ev, [&](skynet::Alert a) {
            alerts.push_back(a);
        });
    }

    std::cout << "Replayed " << event_count << " events.\n";
    std::cout << "Captured " << alerts.size() << " alerts.\n";

    std::set<std::string> rules_fired;
    for (const auto& a : alerts) {
        std::cout << "  - Alert [" << a.rule_id << "] " << a.explanation.substr(0, 60) << "...\n";
        rules_fired.insert(a.rule_id);
    }

    // Verify key detection rules fired
    assert(rules_fired.count("brute_force_success") > 0);
    assert(rules_fired.count("account_persistence") > 0);
    assert(rules_fired.count("usb_execution") > 0);
    assert(rules_fired.count("web_to_shell") > 0);
    assert(rules_fired.count("download_to_run") > 0);
    assert(rules_fired.count("log_tampering") > 0);

    std::cout << "[PASS] ALL 6 ATTACK SCENARIO RULES VERIFIED IN REPLAY!\n";
    return 0;
}

