#pragma once
// SkyNet — USB/Device Collector
// Monitors USB device plug/unplug, mounts, and execution from removable media.

#include "collector.h"
#include "../utils/uuid.h"
#include <set>
#include <map>

namespace skynet {

class USBCollector : public Collector {
public:
    std::string name() const override { return "usb"; }
    bool enabled() const override { return enabled_; }
    bool init(const Config& config) override;
    void collect(const EventCallback& emit) override;
    CollectorStatus status() const override;

private:
    bool enabled_ = true;
    CollectorStatus status_{"usb"};

    struct USBDevice {
        std::string bus_id;      // e.g. "1-1"
        std::string vendor_id;
        std::string product_id;
        std::string serial;
        std::string manufacturer;
        std::string product;
        std::string dev_type;    // "storage", "hid", etc.
    };

    // Known USB devices
    std::set<std::string> known_devices_;  // by bus_id
    // Known mounts (mount point -> device)
    std::map<std::string, std::string> known_mounts_;

    std::vector<USBDevice> scan_usb_devices();
    std::map<std::string, std::string> scan_mounts();
    bool is_removable_mount(const std::string& mount_point);
    std::string get_device_type(const std::string& bus_id);
};

} // namespace skynet
