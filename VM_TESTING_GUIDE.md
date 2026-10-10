# SkyNet VM Testing & Operations Guide

This document explains the setup, architecture, troubleshooting, and testing procedures used for verifying the **SkyNet** Linux endpoint security agent in an isolated, PII-free Ubuntu environment.

---

## 1. Environment & Architecture Overview

### Why an Isolated VM?
SkyNet is a Linux-native endpoint detection and response (EDR) agent written in C++17. It monitors Linux OS telemetry including:
- `/var/log/auth.log` and PAM for authentication events
- `/proc` filesystem and process states
- `/proc/net/` and socket connections for network telemetry
- `/media` and `udisks` for USB storage activity
- `inotify` file watchers for system path integrity
- Local disk spooling and offline queuing

To test these Linux-specific collectors in a clean environment without leaking personal paths, host usernames, or development artifacts, a dedicated VirtualBox VM named **`SkyNet-Node`** was configured.

### Zero-PII Policy
- No host user home directories or personal paths are exposed to the VM.
- No VirtualBox shared folders are mounted.
- All telemetry fixtures, test events, and configurations use generic enterprise identifiers (`sysadmin`, `/home/user`, `corporate-intranet.local`, etc.).

---

## 2. VirtualBox Display Troubleshooting (Why RDP Was Used)

### The Issue
On Windows 11 systems with multiple displays or high-DPI scaling, VirtualBox 7.x can fail to render the VM window when started in GUI mode (clicking "Show" in VirtualBox Manager does nothing, or the Qt window handle initializes off-screen).

### The Solution: Headless VM + VRDE (Remote Desktop)
Instead of relying on the buggy VirtualBox GUI window, we enabled VirtualBox's native **VRDE** (VirtualBox Remote Desktop Extension) and connected via the built-in Windows Remote Desktop client (`mstsc.exe`):

1. **Configured VRDE on a dedicated local port:**
   ```powershell
   & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "SkyNet-Node" --vrde on
   & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "SkyNet-Node" --vrdeport 33890
   & "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" modifyvm "SkyNet-Node" --vrdeaddress 127.0.0.1
   ```

2. **Connected from Windows:**
   ```powershell
   mstsc.exe /v:localhost:33890
   ```
   This provides direct, responsive display and input access directly into the Ubuntu desktop without dependency on the VirtualBox manager window.

---

## 3. Clipboard Sharing Considerations

### Why Copy/Paste Doesn't Work in the Live ISO
VirtualBox bidirectional clipboard sharing relies on the **VirtualBox Guest Additions** background daemon (`VBoxClient --clipboard`) running inside the guest OS. 

When booting into the live "Try Ubuntu" ISO without a full disk installation:
- Guest Additions kernel modules and user daemons are not running.
- As a result, the RDP clipboard channel between the host and the VM is not bridged.
- Once Ubuntu is installed to disk and Guest Additions (`virtualbox-guest-x11`) are installed, clipboard sharing functions normally.

---

## 4. VirtualBox NAT Networking & Host Communication

### How VirtualBox NAT Routes Traffic
When a VM uses VirtualBox NAT networking:
- **Guest IP:** Typically `10.0.2.15/24` on interface `enp0s3`.
- **Internal Virtual Gateway:** `10.0.2.2`. This is a virtual router maintained by VirtualBox for outbound internet routing and DNS proxying. It does **not** forward arbitrary TCP ports to host loopback.
- **Host Machine's Physical IP:** The guest reaches services running on the Windows host (like an HTTP server or webhook receiver) by connecting to the host's actual local network IP (e.g. `192.168.4.228`), or via an explicit VirtualBox port forward rule.

### Live ISO Network Activation
In Ubuntu 24.04 live sessions, NetworkManager handles the virtual network interface (`enp0s3`). If network connectivity is initially inactive:

```bash
# Check current interface and IP status
ip a

# Check routing table
ip r

# Force NetworkManager to connect and acquire DHCP
sudo nmcli device connect enp0s3
```

---

## 5. Transferring & Testing SkyNet

### Step 1: Host File Server
On the Windows host, the project archive `skynet.tar.gz` is served via Python:

```powershell
# From the project root
python -m http.server 8888
```

### Step 2: Download Archive in the VM
In the VM terminal (via RDP):

```bash
# Download archive from host LAN IP
wget http://192.168.4.228:8888/skynet.tar.gz

# Extract
tar -xzvf skynet.tar.gz
cd skynet
```

### Step 3: Automated Build & Verification
Run the included VM test script:

```bash
bash scripts/test_in_vm.sh
```

This script automatically:
1. Installs build dependencies (`build-essential`, `cmake`) if not present.
2. Compiles the agent using CMake and GCC (`-std=c++17`).
3. Executes the full test suite:
   - `test_schema`: Validates JSON schema generation and canonical telemetry types.
   - `test_correlator`: Validates all 6 security attack scenario detection rules:
     - SSH Brute Force
     - Privilege Escalation (`sudo` to root + sensitive file read)
     - Ransomware (burst file modifications + note dropped)
     - Persistence (cron / systemd modification)
     - Data Exfiltration (large outbound payload to unusual port)
     - USB Data Copy (removable device mount + high write volume)
   - `test_fixture_replay`: Replays reference telemetry fixtures and verifies alert generation.
4. Verifies the CLI binary (`skynet-agent --help` and replay mode).

### Step 4: Running the Live Agent
To launch the agent for live system monitoring:

```bash
cd build
sudo ./skynet-agent --config ../config/skynet.json --debug
```

To run the agent in the background as a service or pipe output:
- Telemetry events are written to the configured spool file (default: `events.jsonl`).
- Correlated security alerts are written to `alerts.json`.
- Batched payloads ready for backend ingestion are dispatched to the configured HTTP transport endpoint.

---

## 6. Quick Reference Commands

### On Windows Host
| Action | Command |
|---|---|
| Start VM headless | `& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" startvm "SkyNet-Node" --type headless` |
| Connect to VM Display | `mstsc.exe /v:localhost:33890` |
| Take VM Screenshot | `& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "SkyNet-Node" screenshotpng screen.png` |
| Check VM Status | `& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" showvminfo "SkyNet-Node" --machinereadable` |
| Power Off VM | `& "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe" controlvm "SkyNet-Node" acpipowerbutton` |
| Start Transfer Server | `python -m http.server 8888` |

### Inside Ubuntu VM
| Action | Command |
|---|---|
| Check IP Address | `ip -4 a` |
| Check Gateway Route | `ip r` |
| Download Project | `wget http://192.168.4.228:8888/skynet.tar.gz` |
| Run Test Harness | `bash scripts/test_in_vm.sh` |
| Manual Build | `cmake -B build && cmake --build build -j$(nproc)` |
| Run Unit Tests | `cd build && ctest --output-on-failure` |
| Run Deep System Scan | `./build/skynet-agent --deep-scan report.json` |
| Run Agent CLI | `sudo ./build/skynet-agent --config config/skynet.json` |

