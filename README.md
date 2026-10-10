# Project SkyNet: Creating a Linux Endpoint Security Agent

Application Name: BeneFacto
Version: 1.0.0  
Language: C++17  
Build System: CMake 3.16+  
Target Platform: Linux (Ubuntu 20.04+, Debian 11+, RHEL/Rocky 8+)  

---

## 1. Overview and Architecture

BeneFacto is a Linux endpoint security agent designed with HIDS/EDR detection logic used to capture system telemetry, normalize observations into a canonical JSON schema, run real-time local correlation rules for threat detection, buffer events with disk spooling during backend outages, and stream batched payloads to security ingestion backends.

### Architecture Pipeline

1. **Telemetry Collectors**: Specialized collectors poll and stream data from `/proc`, `/sys`, `/var/log`, and `inotify` watchers across 7 subsystems (authentication, processes, network sockets, file integrity, USB devices, system logs, and application logs).
2. **Canonical Normalizer**: Converts heterogeneous system events into structured, typed objects with UUIDv4 identifiers, UTC timestamps, and standard severities.
3. **Context Enricher and Redactor**: Automatically injects host identity (`host_id`, `hostname`) and redacts passwords, tokens, private keys, and authorization headers from event payloads.
4. **Correlation Engine**: Evaluates streaming observations across a 5-minute sliding window against 6 multi-event attack detection rules, emitting high-confidence alerts upon match.
5. **Event Queue and Disk Spooler**: In-memory ring buffer backed by an encrypted disk spool (`/var/lib/skynet/spool`, 100 MB limit) to prevent data loss during network disconnection or backend backpressure.
6. **Transport Layer**: Dispatches JSON batches to HTTP endpoints or writes formatted events and alerts to disk (`events.jsonl`, `alerts.json`).
7. **Deep Scanner**: Standalone or scheduled inventory scanner for installed packages, desktop software, database instances, systemd services, and SUID/SGID privileged binaries.

---

## 2. Canonical Event Schema

Every observation captured by any collector conforms to the following schema:

```json
{
  "event_id": "00000000-0000-4000-8000-000000000002",
  "schema_version": "1.0.0",
  "event_type": "auth.login_failed",
  "category": "auth",
  "timestamp": "2026-10-04T12:01:01Z",
  "observed_at": "2026-10-04T12:01:01Z",
  "host_id": "be7a4e61-9c88-4fb0-a29d-43cf1812e911",
  "hostname": "prod-srv-01",
  "actor": "192.168.1.100",
  "severity": "low",
  "source": "/var/log/auth.log",
  "collector_status": "ok",
  "related_event_ids": [],
  "details": {
    "auth_method": "password",
    "ip": "192.168.1.100",
    "port": 48922,
    "user": "admin"
  }
}
```

### Enumerations

- **Severity**: `info`, `low`, `medium`, `high`, `critical`
- **Category**: `auth`, `process`, `file`, `network`, `system`, `usb`, `application`, `error`, `agent`

---

## 3. Telemetry Collectors

| Collector | Data Sources | Monitored Activity | Default Interval |
|---|---|---|---|
| **Auth** | `/var/log/auth.log`, `/var/log/secure` | Failed and successful logins, sudo elevations, user creation, group changes | 5s |
| **Process** | `/proc`, `/proc/[pid]/stat`, `/proc/[pid]/cmdline` | Process lifecycles, PID/PPID hierarchy, command lines, memory spikes, `/tmp` execution | 10s |
| **Network** | `/proc/net/tcp`, `/proc/net/udp`, `/proc/net/arp` | Active sockets, listening ports, outbound connections, ARP cache changes | 15s |
| **File** | Watched directories (`/etc`, `/root`, `/home`) | File creation, modification, deletion, permission changes, `/etc/shadow` access via inotify | 10s |
| **USB** | `/sys/bus/usb/devices`, `/proc/mounts` | Device connection, mounting, unmounting, binary execution from removable media | 5s |
| **System** | `/var/log/syslog`, `/dev/kmsg` | Kernel panics, segfaults, OOM kills, permission denials, log truncation | 10s |
| **Application** | Web/DB logs, crontabs, browser configs, `/dev/video*` | 404 scanning, SQL auth failures, cron persistence, extensions, camera/mic access | 15s |

---

## 4. Threat Correlation Rules

The correlation engine maintains state across a 5-minute sliding window to identify multi-stage attack scenarios:

### Rule 1: Brute-Force Success (`brute_force_success`)
- **Trigger**: 5 or more `auth.login_failed` events from the same source IP or user followed by `auth.login_success` or `auth.root_login`.
- **Severity**: Critical (Confidence: 0.95)
- **Explanation**: Indicates automated credential guessing succeeded.

### Rule 2: Account Persistence (`account_persistence`)
- **Trigger**: `auth.user_created` followed immediately by `auth.group_change` adding that account to `sudo`, `wheel`, or `admin`.
- **Severity**: Critical (Confidence: 0.90)
- **Explanation**: Common pattern for establishing backdoor persistence.

### Rule 3: Removable Media Execution (`usb_execution`)
- **Trigger**: `usb.device_connected` followed by `usb.drive_mounted`, followed by `process.started` where the binary path is located inside the mount point.
- **Severity**: Critical (Confidence: 0.85)
- **Explanation**: Indicates USB-delivered payload or automated autorun execution.

### Rule 4: Web Server Interactive Shell (`web_to_shell`)
- **Trigger**: A web server daemon (`nginx`, `apache2`, `httpd`, `node`, `php-fpm`) spawns a shell or interpreter (`bash`, `sh`, `python`, `perl`, `ruby`).
- **Severity**: Critical (Confidence: 0.90)
- **Explanation**: Web shell execution or remote code execution vulnerability.

### Rule 5: Download Followed by Execution (`download_to_run`)
- **Trigger**: File dropped into `~/Downloads` followed by an execution event of that file.
- **Severity**: High (Confidence: 0.80)
- **Explanation**: Drive-by download or phishing payload execution.

### Rule 6: Log Tampering (`log_tampering`)
- **Trigger**: `system.log_tampering` (file truncation or clearing) occurring within the same time window as other events with severity medium or higher.
- **Severity**: Critical (Confidence: 0.85)
- **Explanation**: Attacker clearing system logs to cover recent activity.

---

## 5. Security and Privacy Safeguards

- **Secret Redaction**: Regex-based sanitization strips passwords (`password=***`), API tokens (`Bearer ***`), SSH private keys, and long base64 strings prior to queuing or disk output.
- **Zero-PII Testing**: Telemetry fixtures and test cases use standardized enterprise placeholders (`sysadmin`, `/home/user`, `corporate-intranet.local`) rather than personal host paths.
- **Resilient Spooling**: In-memory ring buffer (10,000 events) flushes to disk when backend connections fail, preventing process memory exhaustion.
- **Log Rotation Handling**: Log watchers track underlying file inodes and file offsets to handle `logrotate` truncation and replacement without event loss.

---

## 6. Build and Verification

### Prerequisites
- C++17 compiler (GCC 9+ or Clang 10+)
- CMake 3.16+
- POSIX threads (`pthread`)

### Install CMake and Build Essentials
```bash
sudo apt-get update
sudo apt-get install -y build-essential cmake
```

### Compilation

```bash
mkdir build
cd build
cmake ..
cmake --build .
```

### Running the Test Suite

```bash
# Schema validation and redactor tests
./test_schema

# Attack scenario correlation rules tests
./test_correlator

# Fixture replay verification (verifies all 6 attack rules trigger on reference data)
./test_fixture_replay

# Deep scanner component tests
./test_deep_scan

# Run all tests via CTest
ctest --output-on-failure
```

---

## 7. CLI Usage

```bash
# Start live monitoring with default configuration:
./skynet-agent --config config/skynet.json

# Start live monitoring with verbose debug logs:
./skynet-agent --config config/skynet.json --debug

# Replay an event fixture file:
./skynet-agent --replay fixtures/events.jsonl

# Run a deep system inventory scan (packages, apps, databases, SUID binaries):
./skynet-agent --deep-scan

# Save deep scan inventory to a JSON file:
./skynet-agent --deep-scan scan_report.json

# Target a specific directory for deep binary scanning:
./skynet-agent --deep-scan scan_report.json --scan-dir /opt
```

---

## 8. Backend Handoff Fixtures

Reference fixtures for backend engineers implementing ingestion APIs are located in `fixtures/`:

- `fixtures/batch_payload.json`: Full HTTP POST payload containing host snapshot, event batch, and correlated alerts.
- `fixtures/events.jsonl`: 21 chronological events covering baseline activity and attack chains.
- `fixtures/alerts.json`: The 6 corresponding alerts generated by the correlation engine.
- `fixtures/host.json`: Host metadata schema snapshot.
- `fixtures/BACKEND_SCHEMA_GUIDE.md`: Schema, field types, and database indexing recommendations.
