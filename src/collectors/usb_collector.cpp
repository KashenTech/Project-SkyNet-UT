// SkyNet — USB Collector Implementation
// Monitors /sys/bus/usb/devices and /proc/mounts for USB device activity.

#include "skynet/collectors/usb_collector.h"
#include "skynet/utils/logger.h"
#include <dirent.h>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <sys/stat.h>
#include <cstring>

namespace skynet {

static std::string now_utc() {
    auto now = std::chrono::system_clock::now();
    auto t   = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&t, &tm);
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

static std::string read_sysfs(const std::string& path) {
    std::ifstream f(path);
    if (!f.is_open()) return "";
    std::string val;
    std::getline(f, val);
    // Trim trailing whitespace
    while (!val.empty() && (val.back() == '\n' || val.back() == '\r' || val.back() == ' '))
        val.pop_back();
    return val;
}

bool USBCollector::init(const Config& config) {
    enabled_ = config.enable_usb;
    if (!enabled_) return true;

    status_.enabled = true;
    struct stat st{};
    status_.accessible = (stat("/sys/bus/usb/devices", &st) == 0);
    if (!status_.accessible) {
        status_.last_error = "/sys/bus/usb/devices not accessible";
        LOG_WARN("usb", status_.last_error);
    }
    return true;
}

std::vector<USBCollector::USBDevice> USBCollector::scan_usb_devices() {
    std::vector<USBDevice> devices;
    std::string base = "/sys/bus/usb/devices";

    DIR* dir = opendir(base.c_str());
    if (!dir) return devices;

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name == "." || name == "..") continue;
        // Skip USB hubs (contain ':')
        if (name.find(':') != std::string::npos) continue;

        std::string dev_path = base + "/" + name;
        std::string vendor_id = read_sysfs(dev_path + "/idVendor");
        std::string product_id = read_sysfs(dev_path + "/idProduct");

        // Skip entries without vendor/product (root hubs)
        if (vendor_id.empty() || product_id.empty()) continue;

        USBDevice dev;
        dev.bus_id       = name;
        dev.vendor_id    = vendor_id;
        dev.product_id   = product_id;
        dev.serial       = read_sysfs(dev_path + "/serial");
        dev.manufacturer = read_sysfs(dev_path + "/manufacturer");
        dev.product      = read_sysfs(dev_path + "/product");
        dev.dev_type     = get_device_type(dev_path);

        devices.push_back(dev);
    }
    closedir(dir);
    return devices;
}

std::string USBCollector::get_device_type(const std::string& bus_id) {
    // Read bInterfaceClass from the interface subdirectory
    // Class 08 = Mass Storage, Class 03 = HID
    std::string dev_path = "/sys/bus/usb/devices/" + bus_id;

    DIR* dir = opendir(dev_path.c_str());
    if (!dir) return "unknown";

    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if (name.find(':') == std::string::npos) continue;

        std::string iface_class = read_sysfs(dev_path + "/" + name + "/bInterfaceClass");
        if (iface_class == "08") { closedir(dir); return "storage"; }
        if (iface_class == "03") { closedir(dir); return "hid"; }
        if (iface_class == "01") { closedir(dir); return "audio"; }
        if (iface_class == "0e") { closedir(dir); return "video"; }
        if (iface_class == "02") { closedir(dir); return "comm"; }
    }
    closedir(dir);
    return "other";
}

std::map<std::string, std::string> USBCollector::scan_mounts() {
    std::map<std::string, std::string> mounts;
    std::ifstream f("/proc/mounts");
    if (!f.is_open()) return mounts;

    std::string line;
    while (std::getline(f, line)) {
        std::istringstream iss(line);
        std::string device, mount_point, fstype;
        iss >> device >> mount_point >> fstype;

        if (is_removable_mount(mount_point)) {
            mounts[mount_point] = device;
        }
    }
    return mounts;
}

bool USBCollector::is_removable_mount(const std::string& mount_point) {
    return mount_point.find("/media/") == 0 ||
           mount_point.find("/mnt/") == 0;
}

void USBCollector::collect(const EventCallback& emit) {
    if (!enabled_) return;

    std::string ts = now_utc();

    // Track USB device insertions and removals
    auto devices = scan_usb_devices();
    std::set<std::string> current_devices;

    for (const auto& dev : devices) {
        current_devices.insert(dev.bus_id);

        // New device plugged in
        if (known_devices_.find(dev.bus_id) == known_devices_.end()) {
            Severity sev = Severity::Medium;
            // Storage devices or HID (keyboard emulators) are higher severity
            if (dev.dev_type == "storage" || dev.dev_type == "hid") {
                sev = Severity::High;
            }

            nlohmann::json details = {
                {"bus_id", dev.bus_id},
                {"vendor_id", dev.vendor_id},
                {"product_id", dev.product_id},
                {"serial", dev.serial},
                {"manufacturer", dev.manufacturer},
                {"product", dev.product},
                {"device_type", dev.dev_type}
            };

            Event e;
            e.event_id       = UUID::generate();
            e.schema_version = SCHEMA_VERSION;
            e.event_type     = "usb.device_connected";
            e.category       = Category::USB;
            e.timestamp      = ts;
            e.observed_at    = ts;
            e.actor          = "device=" + dev.vendor_id + ":" + dev.product_id;
            e.severity       = sev;
            e.source         = "/sys/bus/usb/devices";
            e.details        = details;
            e.collector_status = "ok";

            emit(e);
            status_.events_emitted++;
        }
    }

    // Device removed
    for (const auto& bus_id : known_devices_) {
        if (current_devices.find(bus_id) == current_devices.end()) {
            nlohmann::json details = {{"bus_id", bus_id}};

            Event e;
            e.event_id       = UUID::generate();
            e.schema_version = SCHEMA_VERSION;
            e.event_type     = "usb.device_disconnected";
            e.category       = Category::USB;
            e.timestamp      = ts;
            e.observed_at    = ts;
            e.actor          = "device=" + bus_id;
            e.severity       = Severity::Info;
            e.source         = "/sys/bus/usb/devices";
            e.details        = details;
            e.collector_status = "ok";

            emit(e);
            status_.events_emitted++;
        }
    }

    known_devices_ = current_devices;

    // Track new filesystem mounts
    auto mounts = scan_mounts();
    for (const auto& [mount_point, device] : mounts) {
        if (known_mounts_.find(mount_point) == known_mounts_.end()) {
            nlohmann::json details = {
                {"mount_point", mount_point},
                {"device", device}
            };

            Event e;
            e.event_id       = UUID::generate();
            e.schema_version = SCHEMA_VERSION;
            e.event_type     = "usb.drive_mounted";
            e.category       = Category::USB;
            e.timestamp      = ts;
            e.observed_at    = ts;
            e.actor          = "device=" + device;
            e.severity       = Severity::High;
            e.source         = "/proc/mounts";
            e.details        = details;
            e.collector_status = "ok";

            emit(e);
            status_.events_emitted++;
        }
    }

    known_mounts_ = mounts;
    status_.last_collect = ts;
    status_.accessible = true;
}

CollectorStatus USBCollector::status() const {
    return status_;
}

} // namespace skynet
