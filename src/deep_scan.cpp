#include "skynet/deep_scan.h"
#include "skynet/utils/logger.h"
#include "skynet/utils/time_utils.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <chrono>
#include <iomanip>
#include <sys/stat.h>

#ifndef S_ISUID
#define S_ISUID 04000
#endif
#ifndef S_ISGID
#define S_ISGID 02000
#endif

namespace fs = std::filesystem;

namespace skynet {

static std::string get_scan_time() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
#if defined(_WIN32)
    gmtime_s(&tm, &t);
#else
    gmtime_r(&t, &tm);
#endif
    std::ostringstream ss;
    ss << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

static std::string get_host_name() {
    std::ifstream f("/etc/hostname");
    if (f.is_open()) {
        std::string name;
        if (std::getline(f, name) && !name.empty()) {
            return name;
        }
    }
    return "localhost";
}

void DeepScanner::scan_packages(DeepScanReport& report) {
    // Debian / Ubuntu status database
    std::string dpkg_path = "/var/lib/dpkg/status";
    std::ifstream file(dpkg_path);
    if (!file.is_open()) {
        return;
    }

    std::string line;
    std::string current_pkg;
    std::string current_ver;
    std::string current_arch;
    std::string current_desc;
    bool is_installed = false;

    auto commit_package = [&]() {
        if (!current_pkg.empty() && is_installed) {
            report.total_packages++;
            if (report.installed_packages.size() < 100) {
                report.installed_packages.push_back({
                    {"package", current_pkg},
                    {"version", current_ver},
                    {"architecture", current_arch},
                    {"description", current_desc}
                });
            }
        }
        current_pkg.clear();
        current_ver.clear();
        current_arch.clear();
        current_desc.clear();
        is_installed = false;
    };

    while (std::getline(file, line)) {
        if (line.empty()) {
            commit_package();
            continue;
        }

        if (line.rfind("Package: ", 0) == 0) {
            current_pkg = line.substr(9);
        } else if (line.rfind("Version: ", 0) == 0) {
            current_ver = line.substr(9);
        } else if (line.rfind("Architecture: ", 0) == 0) {
            current_arch = line.substr(14);
        } else if (line.rfind("Status: ", 0) == 0) {
            if (line.find("installed") != std::string::npos &&
                line.find("not-installed") == std::string::npos) {
                is_installed = true;
            }
        } else if (line.rfind("Description: ", 0) == 0) {
            current_desc = line.substr(13);
        }
    }
    commit_package();
}

void DeepScanner::scan_desktop_applications(DeepScanReport& report) {
    std::vector<std::string> app_dirs = {
        "/usr/share/applications",
        "/usr/local/share/applications",
        "/var/lib/snapd/desktop/applications"
    };

    for (const auto& dir : app_dirs) {
        std::error_code ec;
        if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec)) continue;

        for (const auto& entry : fs::directory_iterator(dir, ec)) {
            if (ec) break;
            if (entry.path().extension() == ".desktop") {
                std::ifstream f(entry.path().string());
                if (!f.is_open()) continue;

                std::string line;
                std::string app_name;
                std::string app_exec;
                std::string categories;
                bool is_app = true;

                while (std::getline(f, line)) {
                    if (line.rfind("Name=", 0) == 0 && app_name.empty()) {
                        app_name = line.substr(5);
                    } else if (line.rfind("Exec=", 0) == 0 && app_exec.empty()) {
                        app_exec = line.substr(5);
                    } else if (line.rfind("Categories=", 0) == 0 && categories.empty()) {
                        categories = line.substr(11);
                    } else if (line.rfind("NoDisplay=true", 0) == 0) {
                        is_app = false;
                    }
                }

                if (is_app && !app_name.empty()) {
                    report.total_applications++;
                    report.desktop_applications.push_back({
                        {"name", app_name},
                        {"exec", app_exec},
                        {"categories", categories},
                        {"desktop_file", entry.path().filename().string()}
                    });
                }
            }
        }
    }
}

void DeepScanner::scan_databases(DeepScanReport& report) {
    struct DbTarget {
        std::string name;
        std::vector<std::string> indicator_paths;
    };

    std::vector<DbTarget> databases = {
        {"MySQL / MariaDB", {"/var/lib/mysql", "/etc/mysql", "/usr/bin/mysqld", "/usr/sbin/mysqld"}},
        {"PostgreSQL", {"/var/lib/postgresql", "/etc/postgresql", "/usr/lib/postgresql"}},
        {"Redis", {"/var/lib/redis", "/etc/redis", "/usr/bin/redis-server"}},
        {"MongoDB", {"/var/lib/mongodb", "/etc/mongod.conf", "/usr/bin/mongod"}},
        {"SQLite3", {"/usr/bin/sqlite3", "/usr/lib/x86_64-linux-gnu/libsqlite3.so.0"}}
    };

    for (const auto& db : databases) {
        bool found = false;
        for (const auto& path : db.indicator_paths) {
            std::error_code ec;
            if (fs::exists(path, ec)) {
                found = true;
                break;
            }
        }
        if (found) {
            report.detected_databases.push_back(db.name);
        }
    }
}

void DeepScanner::scan_services(DeepScanReport& report) {
    std::vector<std::string> service_dirs = {
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system"
    };

    for (const auto& dir : service_dirs) {
        std::error_code ec;
        if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec)) continue;

        for (const auto& entry : fs::directory_iterator(dir, ec)) {
            if (ec) break;
            if (entry.path().extension() == ".service") {
                report.total_services++;
                if (report.system_services.size() < 50) {
                    report.system_services.push_back({
                        {"service_name", entry.path().filename().string()},
                        {"path", entry.path().string()}
                    });
                }
            }
        }
    }
}

void DeepScanner::scan_binaries(DeepScanReport& report, const std::string& custom_dir) {
    std::vector<std::string> target_dirs;
    if (!custom_dir.empty()) {
        target_dirs.push_back(custom_dir);
    } else {
        target_dirs = {
            "/bin", "/sbin",
            "/usr/bin", "/usr/sbin",
            "/usr/local/bin", "/usr/local/sbin",
            "/opt"
        };
    }

    for (const auto& dir : target_dirs) {
        std::error_code ec;
        if (!fs::exists(dir, ec) || !fs::is_directory(dir, ec)) continue;

        auto it = fs::directory_iterator(dir, fs::directory_options::skip_permission_denied, ec);
        for (const auto& entry : it) {
            if (ec) break;
            std::error_code file_ec;
            if (!entry.is_regular_file(file_ec)) continue;

            report.total_binaries++;

            // Inspect permissions for SUID/SGID privilege escalation risk
            auto perms = entry.status(file_ec).permissions();
            bool is_suid = false;
            bool is_sgid = false;

            if ((perms & fs::perms::set_uid) != fs::perms::none) is_suid = true;
            if ((perms & fs::perms::set_gid) != fs::perms::none) is_sgid = true;

            // Also check POSIX stat bits directly if on Unix
            struct stat st{};
            if (stat(entry.path().string().c_str(), &st) == 0) {
                if (st.st_mode & S_ISUID) is_suid = true;
                if (st.st_mode & S_ISGID) is_sgid = true;
            }

            if (is_suid || is_sgid) {
                report.privileged_binaries.push_back({
                    {"path", entry.path().string()},
                    {"filename", entry.path().filename().string()},
                    {"size", entry.file_size(file_ec)},
                    {"is_suid", is_suid},
                    {"is_sgid", is_sgid}
                });
            }
        }
    }
}

DeepScanReport DeepScanner::run_scan(const std::string& custom_target_dir) {
    DeepScanReport report;
    report.timestamp = get_scan_time();
    report.hostname = get_host_name();

    scan_packages(report);
    scan_desktop_applications(report);
    scan_databases(report);
    scan_services(report);
    scan_binaries(report, custom_target_dir);

    return report;
}

nlohmann::json DeepScanner::to_json(const DeepScanReport& report) const {
    nlohmann::json j;
    j["timestamp"] = report.timestamp;
    j["hostname"] = report.hostname;
    j["summary"] = {
        {"total_packages", report.total_packages},
        {"total_applications", report.total_applications},
        {"total_binaries", report.total_binaries},
        {"total_services", report.total_services},
        {"detected_databases_count", report.detected_databases.size()},
        {"privileged_binaries_count", report.privileged_binaries.size()}
    };
    j["detected_databases"] = report.detected_databases;
    j["privileged_binaries"] = report.privileged_binaries;
    j["desktop_applications"] = report.desktop_applications;
    j["system_services"] = report.system_services;
    j["installed_packages_sample"] = report.installed_packages;
    return j;
}

void DeepScanner::print_summary(const DeepScanReport& report, std::ostream& out) const {
    out << "\n=========================================\n"
        << "      SkyNet Deep System Inventory       \n"
        << "=========================================\n"
        << " Timestamp:            " << report.timestamp << "\n"
        << " Hostname:             " << report.hostname << "\n"
        << " Total Packages:       " << report.total_packages << "\n"
        << " Desktop Applications: " << report.total_applications << "\n"
        << " Executable Binaries:  " << report.total_binaries << "\n"
        << " System Services:      " << report.total_services << "\n"
        << " SUID/SGID Binaries:   " << report.privileged_binaries.size() << "\n";

    out << "\n--- Databases Detected ---\n";
    if (report.detected_databases.empty()) {
        out << "  None detected\n";
    } else {
        for (const auto& db : report.detected_databases) {
            out << "  [+] " << db << "\n";
        }
    }

    out << "\n--- High-Risk Privileged Binaries (SUID/SGID) ---\n";
    if (report.privileged_binaries.empty()) {
        out << "  No SUID/SGID binaries found in scanned paths.\n";
    } else {
        for (const auto& bin : report.privileged_binaries) {
            out << "  [!] " << bin.value("path", "")
                << " (SUID: " << (bin.value("is_suid", false) ? "yes" : "no")
                << ", SGID: " << (bin.value("is_sgid", false) ? "yes" : "no") << ")\n";
        }
    }

    out << "\n--- Installed Desktop Applications (Sample) ---\n";
    size_t app_count = std::min(report.desktop_applications.size(), size_t(10));
    for (size_t i = 0; i < app_count; ++i) {
        out << "  * " << report.desktop_applications[i].value("name", "")
            << " (" << report.desktop_applications[i].value("desktop_file", "") << ")\n";
    }
    if (report.desktop_applications.size() > 10) {
        out << "  ... and " << (report.desktop_applications.size() - 10) << " more.\n";
    }
    out << "=========================================\n";
}

bool DeepScanner::save_report(const DeepScanReport& report, const std::string& output_path) const {
    std::ofstream out(output_path);
    if (!out.is_open()) {
        return false;
    }
    out << to_json(report).dump(2) << "\n";
    return true;
}

} // namespace skynet
