#include "gcad/scanner/deep_scanner.hpp"
#include "gcad/scanner/signature_db.hpp"
#include "gcad/scanner/heuristic_rules.hpp"
#include "gcad/platform/platform_compat.hpp"

namespace gcad {

static SignatureDB    g_sig_db;
static HeuristicEngine g_heuristic;

DeepScanner::DeepScanner() : pool_(std::max(2u, std::thread::hardware_concurrency() / 2)) {}
DeepScanner::~DeepScanner() {
    cancel_scan();
    if (monitor_thread_.joinable()) monitor_thread_.join();
}

void DeepScanner::start_scan(ScanMode mode, const std::filesystem::path& target) {
    if (scanning_.load()) return;
    if (monitor_thread_.joinable()) monitor_thread_.join();

    scanning_.store(true);
    cancel_.store(false);
    current_mode_ = mode;
    files_scanned_.store(0);
    threats_found_.store(0);
    files_total_.store(0);
    scan_start_ = std::chrono::steady_clock::now();
    {
        std::lock_guard lk(mtx_);
        results_.clear();
        current_file_.clear();
    }

    monitor_thread_ = std::thread([this, mode, target]() {
      try {
        std::vector<std::filesystem::path> paths;
        {
            std::lock_guard lk(mtx_);
            current_file_ = "Enumerating files...";
        }

        if (mode == ScanMode::CUSTOM && !target.empty()) {
            enumerate_files(target, paths);
        } else if (mode == ScanMode::MEMORY) {
            auto procs = platform::enumerate_processes();
            for (auto& pr : procs) {
                if (!pr.path.empty() && platform::file_exists(pr.path))
                    paths.push_back(pr.path);
            }
        } else if (mode == ScanMode::QUICK) {
            auto sys_paths = platform::get_system_scan_paths();
            for (auto& p : sys_paths) {
                if (cancel_.load()) break;
                enumerate_files(p, paths);
            }
        } else {
            auto sys_paths = platform::get_system_scan_paths();
            for (auto& p : sys_paths) {
                if (cancel_.load()) break;
                enumerate_files(p, paths);
            }
#ifdef GCAD_PLATFORM_WINDOWS
            auto* prog_files = std::getenv("ProgramFiles");
            if (prog_files && !cancel_.load()) enumerate_files(prog_files, paths);
#endif
        }

        if (cancel_.load()) { scanning_.store(false); return; }

        files_total_.store(paths.size());
        GCAD_LOG(INFO, "Scan started: " + std::to_string(paths.size()) + " files");

        for (auto& p : paths) {
            if (cancel_.load()) break;
            pool_.enqueue([this, path = p]() {
                if (cancel_.load()) return;
                {
                    std::lock_guard lk(mtx_);
                    current_file_ = path.string();
                }
                scan_file(path);
                files_scanned_.fetch_add(1);
            });
        }

        while (files_scanned_.load() < files_total_.load() && !cancel_.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        scanning_.store(false);
        GCAD_LOG(INFO, "Scan complete: " + std::to_string(threats_found_.load()) + " threats found");
      } catch (const std::exception& ex) {
        GCAD_LOG(ERR, std::string("Scan aborted: ") + ex.what());
        scanning_.store(false);
      } catch (...) {
        GCAD_LOG(ERR, "Scan aborted: unknown exception");
        scanning_.store(false);
      }
    });
}

void DeepScanner::cancel_scan() {
    cancel_.store(true);
    scanning_.store(false);
}

ScanProgress DeepScanner::progress() const {
    ScanProgress p;
    p.mode = current_mode_;
    p.files_total = files_total_.load();
    p.files_scanned = files_scanned_.load();
    p.threats_found = threats_found_.load();
    p.active = scanning_.load();
    auto elapsed = std::chrono::steady_clock::now() - scan_start_;
    p.elapsed_seconds = std::chrono::duration<double>(elapsed).count();
    {
        std::lock_guard lk(const_cast<std::mutex&>(mtx_));
        p.current_file = current_file_;
    }
    return p;
}

std::vector<ScanResult> DeepScanner::get_results() const {
    std::lock_guard lk(const_cast<std::mutex&>(mtx_));
    return results_;
}

void DeepScanner::on_result(std::function<void(const ScanResult&)> cb) {
    result_cb_ = std::move(cb);
}

void DeepScanner::enumerate_files(const std::filesystem::path& root, std::vector<std::filesystem::path>& out) {
    std::error_code ec;
    std::filesystem::recursive_directory_iterator it(root,
        std::filesystem::directory_options::skip_permission_denied, ec);
    if (ec) return;
    const std::filesystem::recursive_directory_iterator end;
    while (it != end) {
        if (cancel_.load()) return;
        const auto& e = *it;
        std::error_code fec;
        if (e.is_regular_file(fec) && !fec) {
            auto sz = e.file_size(fec);
            if (!fec && sz != 0 && sz <= 256 * 1024 * 1024)
                out.push_back(e.path());
        }
        it.increment(ec);
        if (ec) return;
    }
}

bool DeepScanner::scan_file(const std::filesystem::path& path) {
    std::error_code ec;
    auto sz = std::filesystem::file_size(path, ec);
    if (ec || sz == 0) return false;
    if (sz > 256 * 1024 * 1024) return false;

    std::ifstream f(path, std::ios::binary);
    if (!f) return false;

    std::vector<uint8_t> data(static_cast<size_t>(sz));
    f.read(reinterpret_cast<char*>(data.data()), sz);

    ScanResult result;
    result.file_path = path.string();

    bool threat = false;
    ScanResult sig_res, sc_res, pe_res, elf_res, ent_res;
    sig_res.file_path = path.string();
    sc_res.file_path = path.string();
    pe_res.file_path = path.string();
    elf_res.file_path = path.string();
    ent_res.file_path = path.string();

    if (check_signature_match(data, path, sig_res)) {
        result = std::move(sig_res);
        threat = true;
    } else if (check_shellcode_patterns(data, sc_res)) {
        result = std::move(sc_res);
        threat = true;
    } else if (check_pe_header(data, pe_res)) {
        result = std::move(pe_res);
        threat = true;
    } else if (check_elf_header(data, elf_res)) {
        result = std::move(elf_res);
        threat = true;
    } else if (check_entropy_anomaly(data, ent_res)) {
        result = std::move(ent_res);
        threat = true;
    }

    if (threat) {
        threats_found_.fetch_add(1);
        std::lock_guard lk(mtx_);
        results_.push_back(result);
        if (result_cb_) result_cb_(result);
    }
    return threat;
}

bool DeepScanner::check_signature_match(const std::vector<uint8_t>& data,
                                         const std::filesystem::path& path, ScanResult& out) {
    auto match = g_sig_db.scan(data.data(), data.size());
    if (match) {
        out.level = match->sig->level;
        out.category = match->sig->category;
        out.signature_name = match->sig->name;
        out.description = match->sig->description;
        out.matched_bytes.assign(data.begin() + match->offset,
            data.begin() + match->offset + std::min(match->sig->pattern.size(), size_t(32)));
        return true;
    }
    (void)path;
    return false;
}

bool DeepScanner::check_entropy_anomaly(const std::vector<uint8_t>& data, ScanResult& out) {
    double ent = shannon_entropy(data.data(), data.size());
    out.entropy = ent;
    if (ent > 7.8 && data.size() > 4096) {
        out.level = ThreatLevel::HIGH;
        out.category = ThreatCategory::ENTROPY_ANOMALY;
        out.description = "Extremely high entropy (" + std::format("{:.3f}", ent) + ") — packed/encrypted";
        return true;
    }
    return false;
}

bool DeepScanner::check_pe_header(const std::vector<uint8_t>& data, ScanResult& out) {
    if (data.size() < 64) return false;
    if (data[0] != 'M' || data[1] != 'Z') return false;

    uint32_t pe_offset_raw;
    std::memcpy(&pe_offset_raw, &data[60], sizeof(pe_offset_raw));
    const uint64_t pe_offset = pe_offset_raw;
    if (pe_offset + 8 > data.size()) return false;
    if (data[pe_offset] != 'P' || data[pe_offset+1] != 'E') return false;

    uint16_t num_sections;
    std::memcpy(&num_sections, &data[pe_offset + 6], sizeof(num_sections));
    if (num_sections > 96) {
        out.level = ThreatLevel::MEDIUM;
        out.category = ThreatCategory::SUSPICIOUS_BINARY;
        out.description = "PE with abnormal section count: " + std::to_string(num_sections);
        return true;
    }

    auto heuristics = g_heuristic.analyze_binary(data.data(), data.size(), "");
    for (auto& h : heuristics) {
        if (h.confidence > 0.7) {
            out.level = h.level;
            out.category = h.category;
            out.description = h.description;
            return true;
        }
    }
    return false;
}

bool DeepScanner::check_elf_header(const std::vector<uint8_t>& data, ScanResult& out) {
    if (data.size() < 16) return false;
    if (data[0] != 0x7F || data[1] != 'E' || data[2] != 'L' || data[3] != 'F') return false;

    double ent = shannon_entropy(data.data(), std::min(data.size(), size_t(4096)));
    if (ent > 7.5) {
        out.level = ThreatLevel::MEDIUM;
        out.category = ThreatCategory::SUSPICIOUS_BINARY;
        out.description = "ELF binary with high entropy header section";
        return true;
    }
    return false;
}

bool DeepScanner::check_shellcode_patterns(const std::vector<uint8_t>& data, ScanResult& out) {
    static const std::vector<std::vector<uint8_t>> nop_sleds = {
        {0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90},
    };

    for (auto& sled : nop_sleds) {
        for (size_t i = 0; i + sled.size() <= data.size(); ++i) {
            if (std::memcmp(data.data() + i, sled.data(), sled.size()) == 0) {
                if (i + sled.size() + 4 < data.size()) {
                    uint8_t next = data[i + sled.size()];
                    if (next == 0xCC || next == 0xEB || next == 0xE8 || next == 0xE9 || next == 0x68) {
                        out.level = ThreatLevel::CRITICAL;
                        out.category = ThreatCategory::SHELLCODE;
                        out.description = "NOP sled followed by control transfer at offset " + std::to_string(i);
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

} // namespace gcad
