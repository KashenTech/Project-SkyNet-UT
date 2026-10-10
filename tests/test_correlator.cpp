// SkyNet Tests — Correlation Engine Rules Test

#include "skynet/correlator.h"
#include <iostream>
#include <cassert>

skynet::Event make_base_event(const std::string& type, skynet::Category cat, skynet::Severity sev, const std::string& ts) {
    skynet::Event e;
    static int counter = 100;
    e.event_id       = "test-event-" + std::to_string(++counter);
    e.schema_version = skynet::SCHEMA_VERSION;
    e.event_type     = type;
    e.category       = cat;
    e.severity       = sev;
    e.timestamp      = ts;
    e.observed_at    = ts;
    e.host_id        = "test-host";
    e.hostname       = "test-node";
    e.actor          = "test-actor";
    e.source         = "test";
    e.collector_status = "ok";
    return e;
}

void test_rule_brute_force() {
    std::cout << "[TEST] Running test_rule_brute_force...\n";
    skynet::Correlator correlator;
    std::vector<skynet::Alert> alerts;

    auto cb = [&](skynet::Alert a) { alerts.push_back(a); };

    // 5 failed logins
    for (int i = 0; i < 5; ++i) {
        auto e = make_base_event("auth.login_failed", skynet::Category::Auth, skynet::Severity::Low, "2026-10-04T10:00:0" + std::to_string(i) + "Z");
        e.details = {{"ip", "10.0.0.99"}, {"user", "victim"}};
        correlator.process(e, cb);
    }
    assert(alerts.empty());

    // 1 successful login from same IP and user
    auto success = make_base_event("auth.login_success", skynet::Category::Auth, skynet::Severity::Info, "2026-10-04T10:00:06Z");
    success.details = {{"ip", "10.0.0.99"}, {"user", "victim"}};
    correlator.process(success, cb);

    assert(alerts.size() == 1);
    assert(alerts[0].rule_id == "brute_force_success");
    assert(alerts[0].severity == skynet::Severity::Critical);
    assert(alerts[0].related_event_ids.size() == 6);
    std::cout << "  [PASS] Brute-force rule passed: " << alerts[0].explanation << "\n";
}

void test_rule_account_persistence() {
    std::cout << "[TEST] Running test_rule_account_persistence...\n";
    skynet::Correlator correlator;
    std::vector<skynet::Alert> alerts;
    auto cb = [&](skynet::Alert a) { alerts.push_back(a); };

    // 1. User created
    auto e1 = make_base_event("auth.user_created", skynet::Category::Auth, skynet::Severity::Medium, "2026-10-04T10:10:00Z");
    e1.details = {{"account", "infiltrator"}};
    correlator.process(e1, cb);
    assert(alerts.empty());

    // 2. Added to sudo group
    auto e2 = make_base_event("auth.group_change", skynet::Category::Auth, skynet::Severity::High, "2026-10-04T10:10:15Z");
    e2.details = {{"account", "infiltrator"}, {"group", "sudo"}};
    correlator.process(e2, cb);

    assert(alerts.size() == 1);
    assert(alerts[0].rule_id == "account_persistence");
    assert(alerts[0].severity == skynet::Severity::Critical);
    assert(alerts[0].related_event_ids.size() == 2);
    std::cout << "  [PASS] Account persistence rule passed\n";
}

void test_rule_usb_execution() {
    std::cout << "[TEST] Running test_rule_usb_execution...\n";
    skynet::Correlator correlator;
    std::vector<skynet::Alert> alerts;
    auto cb = [&](skynet::Alert a) { alerts.push_back(a); };

    // 1. USB connect
    auto e1 = make_base_event("usb.device_connected", skynet::Category::USB, skynet::Severity::Low, "2026-10-04T10:20:00Z");
    e1.details = {{"vendor_id", "abcd"}, {"product_id", "1234"}};
    correlator.process(e1, cb);

    // 2. Mount
    auto e2 = make_base_event("usb.drive_mounted", skynet::Category::USB, skynet::Severity::Low, "2026-10-04T10:20:05Z");
    e2.details = {{"mount_point", "/mnt/flash"}};
    correlator.process(e2, cb);
    assert(alerts.empty());

    // 3. Process executed from mount
    auto e3 = make_base_event("process.started", skynet::Category::Process, skynet::Severity::High, "2026-10-04T10:20:10Z");
    e3.details = {{"exe", "/mnt/flash/malware"}, {"cmdline", "/mnt/flash/malware"}};
    correlator.process(e3, cb);

    assert(alerts.size() == 1);
    assert(alerts[0].rule_id == "usb_execution");
    assert(alerts[0].related_event_ids.size() == 3);
    std::cout << "  [PASS] USB execution rule passed\n";
}

void test_rule_web_to_shell() {
    std::cout << "[TEST] Running test_rule_web_to_shell...\n";
    skynet::Correlator correlator;
    std::vector<skynet::Alert> alerts;
    auto cb = [&](skynet::Alert a) { alerts.push_back(a); };

    // 1. Web server running (pid 500)
    auto e1 = make_base_event("process.started", skynet::Category::Process, skynet::Severity::Info, "2026-10-04T10:30:00Z");
    e1.details = {{"pid", 500}, {"comm", "nginx"}, {"exe", "/usr/sbin/nginx"}};
    correlator.process(e1, cb);

    // 2. Shell spawned with ppid 500
    auto e2 = make_base_event("process.started", skynet::Category::Process, skynet::Severity::High, "2026-10-04T10:30:05Z");
    e2.details = {{"pid", 600}, {"ppid", 500}, {"comm", "sh"}, {"exe", "/bin/sh"}};
    correlator.process(e2, cb);

    assert(alerts.size() == 1);
    assert(alerts[0].rule_id == "web_to_shell");
    std::cout << "  [PASS] Web-to-shell rule passed\n";
}

void test_rule_download_to_run() {
    std::cout << "[TEST] Running test_rule_download_to_run...\n";
    skynet::Correlator correlator;
    std::vector<skynet::Alert> alerts;
    auto cb = [&](skynet::Alert a) { alerts.push_back(a); };

    // 1. Downloaded file
    auto e1 = make_base_event("file.created", skynet::Category::File, skynet::Severity::Info, "2026-10-04T10:40:00Z");
    e1.details = {{"path", "/home/user/Downloads/dropper.bin"}};
    correlator.process(e1, cb);

    // 2. Executed
    auto e2 = make_base_event("process.started", skynet::Category::Process, skynet::Severity::High, "2026-10-04T10:40:10Z");
    e2.details = {{"exe", "/home/user/Downloads/dropper.bin"}};
    correlator.process(e2, cb);

    assert(alerts.size() == 1);
    assert(alerts[0].rule_id == "download_to_run");
    std::cout << "  [PASS] Download-to-run rule passed\n";
}

int main() {
    std::cout << "=== SkyNet Correlator Rules Tests ===\n";
    test_rule_brute_force();
    test_rule_account_persistence();
    test_rule_usb_execution();
    test_rule_web_to_shell();
    test_rule_download_to_run();
    std::cout << "ALL CORRELATOR TESTS PASSED!\n";
    return 0;
}
