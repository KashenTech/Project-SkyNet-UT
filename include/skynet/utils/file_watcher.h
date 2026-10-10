#pragma once
// SkyNet — Log File Watcher
// Tails log files tracking offsets and inodes to handle rotation.

#include <string>
#include <fstream>
#include <functional>
#include <vector>
#include <sys/stat.h>
#include <unistd.h>

namespace skynet {

/// Watches a log file and delivers new lines, handling rotation.
class FileWatcher {
public:
    explicit FileWatcher(const std::string& path)
        : path_(path) {}

    /// Check for new lines. Calls callback for each new line.
    /// Returns number of lines read.
    int poll(const std::function<void(const std::string&)>& callback) {
        struct stat st{};
        if (stat(path_.c_str(), &st) != 0) {
            return -1; // File doesn't exist
        }

        // Detect rotation: inode changed or file shrunk
        if (st.st_ino != inode_ || st.st_size < offset_) {
            offset_ = 0;
            inode_  = st.st_ino;
        }

        if (static_cast<off_t>(st.st_size) <= static_cast<off_t>(offset_)) {
            return 0; // No new data
        }

        std::ifstream file(path_);
        if (!file.is_open()) return -1;

        file.seekg(offset_);
        std::string line;
        int count = 0;
        while (std::getline(file, line)) {
            if (!line.empty()) {
                callback(line);
                ++count;
            }
        }
        offset_ = file.tellg();
        if (offset_ < 0) offset_ = st.st_size; // EOF fallback

        return count;
    }

    /// Get current offset (for diagnostics).
    off_t offset() const { return offset_; }

    /// Get watched file path.
    const std::string& path() const { return path_; }

    /// Check if the file exists and is readable.
    bool accessible() const {
        return access(path_.c_str(), R_OK) == 0;
    }

private:
    std::string path_;
    off_t       offset_ = 0;
    ino_t       inode_  = 0;
};

} // namespace skynet
