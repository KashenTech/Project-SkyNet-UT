// SkyNet Tests — Schema and Utility Unit Tests

#include "skynet/types.h"
#include "skynet/utils/uuid.h"
#include "skynet/utils/redactor.h"
#include "skynet/config.h"
#include <iostream>
#include <cassert>
#include <regex>

void test_uuid() {
    std::cout << "[TEST] Running test_uuid...\n";
    std::string uuid = skynet::UUID::generate();
    assert(uuid.length() == 36);
    assert(uuid[8] == '-' && uuid[13] == '-' && uuid[18] == '-' && uuid[23] == '-');

    // Check version 4 nibble
    assert(uuid[14] == '4');

    // Check uniqueness
    std::string uuid2 = skynet::UUID::generate();
    assert(uuid != uuid2);
    std::cout << "  [PASS] UUID test passed: " << uuid << "\n";
}

void test_redactor() {
    std::cout << "[TEST] Running test_redactor...\n";
    skynet::Redactor r;

    // Password redaction
    std::string input1 = "user login with password=SuperSecret123 in command line";
    std::string out1 = r.redact(input1);
    assert(out1.find("SuperSecret123") == std::string::npos);
    assert(out1.find("<REDACTED>") != std::string::npos);

    // Token redaction
    std::string input2 = "curl -H 'Authorization: Bearer my-secret-token-xyz' api.com";
    std::string out2 = r.redact(input2);
    assert(out2.find("my-secret-token-xyz") == std::string::npos);

    // Private key redaction
    std::string input3 = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA\n-----END OPENSSH PRIVATE KEY-----";
    std::string out3 = r.redact(input3);
    assert(out3 == "<REDACTED_PRIVATE_KEY>");

    std::cout << "  [PASS] Redactor test passed\n";
}

void test_event_serialization() {
    std::cout << "[TEST] Running test_event_serialization...\n";
    skynet::Event e;
    e.event_id         = "test-uuid-1234";
    e.schema_version   = skynet::SCHEMA_VERSION;
    e.event_type       = "auth.login_failed";
    e.category         = skynet::Category::Auth;
    e.timestamp        = "2026-10-04T12:00:00Z";
    e.observed_at      = "2026-10-04T12:00:01Z";
    e.host_id          = "host-xyz";
    e.hostname         = "srv-01";
    e.actor            = "192.168.1.10";
    e.severity         = skynet::Severity::Low;
    e.source           = "/var/log/auth.log";
    e.details          = {{"ip", "192.168.1.10"}, {"user", "admin"}};
    e.collector_status = "ok";

    nlohmann::json j;
    to_json(j, e);

    assert(j["event_id"] == "test-uuid-1234");
    assert(j["category"] == "auth");
    assert(j["severity"] == "low");
    assert(j["details"]["user"] == "admin");

    // Deserialize back
    skynet::Event deserialized;
    from_json(j, deserialized);

    assert(deserialized.event_id == e.event_id);
    assert(deserialized.category == e.category);
    assert(deserialized.severity == e.severity);
    assert(deserialized.details["ip"] == "192.168.1.10");

    std::cout << "  [PASS] Event serialization test passed\n";
}

void test_config_validation() {
    std::cout << "[TEST] Running test_config_validation...\n";
    skynet::Config cfg;
    auto errors = cfg.validate();
    assert(errors.empty());

    // Invalid batch size
    cfg.batch_size = 0;
    errors = cfg.validate();
    assert(!errors.empty());

    std::cout << "  [PASS] Config validation test passed\n";
}

int main() {
    std::cout << "=== SkyNet Schema & Utils Tests ===\n";
    test_uuid();
    test_redactor();
    test_event_serialization();
    test_config_validation();
    std::cout << "ALL TESTS PASSED!\n";
    return 0;
}
