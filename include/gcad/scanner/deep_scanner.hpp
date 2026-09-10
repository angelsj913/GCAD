#pragma once
#include "../common.hpp"

namespace gcad {

enum class ScanMode : uint8_t {
    QUICK   = 0,
    DEEP    = 1,
    MEMORY  = 2,
    CUSTOM  = 3,
};

struct ScanProgress {
    ScanMode    mode;
    uint64_t    files_total;
    uint64_t    files_scanned;
    uint64_t    threats_found;
    double      elapsed_seconds;
    bool        active;
    std::string current_file;
};

class DeepScanner {
    ThreadPool                           pool_;
    mutable std::mutex                   mtx_;
    std::atomic<bool>                    scanning_{false};
    std::atomic<bool>                    cancel_{false};

    std::atomic<uint64_t> files_total_{0};
    std::atomic<uint64_t> files_scanned_{0};
    std::atomic<uint64_t> threats_found_{0};
    std::string           current_file_;
    std::chrono::steady_clock::time_point scan_start_;
    std::vector<ScanResult>              results_;

    std::thread                          monitor_thread_;
    ScanMode                             current_mode_{ScanMode::DEEP};
    std::function<void(const ScanResult&)> result_cb_;

    bool scan_file(const std::filesystem::path& path);
    bool check_pe_header(const std::vector<uint8_t>& data, ScanResult& out);
    bool check_elf_header(const std::vector<uint8_t>& data, ScanResult& out);
    bool check_shellcode_patterns(const std::vector<uint8_t>& data, ScanResult& out);
    bool check_entropy_anomaly(const std::vector<uint8_t>& data, ScanResult& out);
    bool check_signature_match(const std::vector<uint8_t>& data, const std::filesystem::path& path, ScanResult& out);

    void enumerate_files(const std::filesystem::path& root, std::vector<std::filesystem::path>& out);

public:
    DeepScanner();
    ~DeepScanner();

    void start_scan(ScanMode mode, const std::filesystem::path& target = {});
    void cancel_scan();
    bool is_scanning() const noexcept { return scanning_.load(); }

    ScanProgress progress() const;
    std::vector<ScanResult> get_results() const;
    void on_result(std::function<void(const ScanResult&)> cb);
};

} // namespace gcad
