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
    // Drain any tasks still referencing this/results_/mtx_ before members are destroyed.
    pool_.clear_queue();
    pool_.wait_idle();
}

void DeepScanner::start_scan(ScanMode mode, const std::filesystem::path& target) {
    if (scanning_.load()) return;
    if (monitor_thread_.joinable()) monitor_thread_.join();
    // Make sure the previous scan's worker tasks are fully finished before we
    // reset the progress counters they write to.
    pool_.clear_queue();
    pool_.wait_idle();

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
        // Bound the work so a "Quick" scan stays quick and no scan exhausts memory
        // building its path list.
        const size_t max_files = (mode == ScanMode::QUICK) ? 20000 : 200000;

        std::vector<std::filesystem::path> roots;
        if (mode == ScanMode::CUSTOM) {
            if (!target.empty()) roots.push_back(target);
        } else if (mode == ScanMode::MEMORY) {
            // handled below without file enumeration
        } else if (mode == ScanMode::QUICK) {
#ifdef GCAD_PLATFORM_WINDOWS
            if (auto* p = std::getenv("USERPROFILE")) {
                roots.push_back(std::string(p) + "\\Desktop");
                roots.push_back(std::string(p) + "\\Downloads");
            }
#else
            if (auto* p = std::getenv("HOME")) roots.push_back(p);
#endif
        } else { // DEEP
            for (auto& p : platform::get_system_scan_paths()) roots.push_back(p);
#ifdef GCAD_PLATFORM_WINDOWS
            if (auto* pf = std::getenv("ProgramFiles")) roots.push_back(pf);
#endif
        }

        {
            std::lock_guard lk(mtx_);
            current_file_ = (mode == ScanMode::MEMORY) ? "Enumerating processes..."
                                                       : "Enumerating files...";
        }

        if (mode == ScanMode::MEMORY) {
            auto procs = platform::enumerate_processes();
            if (cancel_.load()) { scanning_.store(false); return; }
            files_total_.store(procs.size());
            GCAD_LOG(INFO, "Memory scan started: " + std::to_string(procs.size()) + " processes");

            for (auto& pr : procs) {
                if (cancel_.load()) break;
                pool_.enqueue([this, pid = pr.pid, pname = pr.name]() {
                    if (!cancel_.load()) {
                        try {
                            {
                                std::lock_guard lk(mtx_);
                                current_file_ = "PID " + std::to_string(pid) + " (" + pname + ")";
                            }
                            scan_process_memory(pid, pname);
                        } catch (...) {}
                    }
                    files_scanned_.fetch_add(1);
                });
            }
        } else {
            std::vector<std::filesystem::path> paths;
            for (auto& r : roots) {
                if (cancel_.load()) break;
                enumerate_files(r, paths, max_files);
                {
                    std::lock_guard lk(mtx_);
                    current_file_ = "Enumerating files... (" + std::to_string(paths.size()) + ")";
                }
            }

            if (cancel_.load()) { scanning_.store(false); return; }

            files_total_.store(paths.size());
            GCAD_LOG(INFO, "Scan started: " + std::to_string(paths.size()) + " files");

            for (auto& p : paths) {
                if (cancel_.load()) break;
                pool_.enqueue([this, path = p]() {
                    if (!cancel_.load()) {
                        try {
                            {
                                std::lock_guard lk(mtx_);
                                current_file_ = path.string();
                            }
                            scan_file(path);
                        } catch (...) {
                            // A single unreadable/oversized file must not stall the scan.
                        }
                    }
                    // Always advance progress so the monitor loop can terminate.
                    files_scanned_.fetch_add(1);
                });
            }
        }

        while (files_scanned_.load() < files_total_.load() && !cancel_.load())
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        scanning_.store(false);
        lifetime_scanned_.fetch_add(files_scanned_.load());
        lifetime_threats_.fetch_add(threats_found_.load());
        if (!cancel_.load()) scans_completed_.fetch_add(1);
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
    pool_.clear_queue();
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
    std::lock_guard lk(cb_mtx_);
    result_cb_ = std::move(cb);
}

void DeepScanner::on_observation(std::function<void(security::SecurityObservation)> cb) {
    std::lock_guard lk(cb_mtx_);
    observation_cb_ = std::move(cb);
}

size_t DeepScanner::signature_count() const {
    return g_sig_db.size();
}

void DeepScanner::enumerate_files(const std::filesystem::path& root,
                                 std::vector<std::filesystem::path>& out, size_t max_files) {
    namespace fs = std::filesystem;
    std::error_code ec;
    if (!fs::exists(root, ec) || ec) return;
    if (out.size() >= max_files) return;

    // Manual DFS with non-recursive iterators: a single unreadable directory or a
    // broken reparse point is skipped instead of aborting the whole tree, and
    // symlinks/junctions are never followed (avoids cycles and cross-volume walks).
    std::vector<fs::path> stack;
    stack.push_back(root);

    while (!stack.empty()) {
        if (cancel_.load() || out.size() >= max_files) return;
        fs::path dir = std::move(stack.back());
        stack.pop_back();

        std::error_code dir_ec;
        fs::directory_iterator it(dir, fs::directory_options::skip_permission_denied, dir_ec);
        if (dir_ec) continue;
        const fs::directory_iterator end;

        for (; it != end; it.increment(dir_ec)) {
            if (dir_ec) break;             // stop this directory, keep the rest of the tree
            if (cancel_.load() || out.size() >= max_files) return;

            const fs::directory_entry& e = *it;
            std::error_code fec;

            if (e.is_symlink(fec)) continue;
            if (e.is_directory(fec) && !fec) {
                stack.push_back(e.path());
                continue;
            }
            if (e.is_regular_file(fec) && !fec) {
                auto sz = e.file_size(fec);
                if (!fec && sz != 0 && sz <= 256 * 1024 * 1024)
                    out.push_back(e.path());
            }
        }
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
    } else {
        std::string ext = path.extension().string();
        for (auto& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));

        if (ext == ".lnk") {
            LolbinExecution le;
            if (lolbins_engine_.inspect_lnk_file(path, le) && le.is_malicious) {
                result.level = le.severity;
                result.category = ThreatCategory::LOLBIN_EXECUTION;
                result.signature_name = "LNK.Weaponized";
                result.description = "Weaponized LNK shortcut: " + le.reason;
                threat = true;
            }
        } else if (ext == ".ps1" || ext == ".vbs" || ext == ".js" || ext == ".bat" || ext == ".cmd" || ext == ".hta") {
            std::string script_str(reinterpret_cast<const char*>(data.data()), data.size());
            auto fe = fileless_engine_.evaluate_script(script_str);
            if (fe.is_malicious) {
                result.level = fe.severity;
                result.category = ThreatCategory::PERSISTENCE_HIJACK;
                result.signature_name = "Script.ObfuscatedAST";
                result.description = "Malicious fileless script: " + fe.reason;
                threat = true;
            }
        }
    }

    if (!threat) {
        if (check_shellcode_patterns(data, sc_res)) {
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
    }

    std::function<void(const ScanResult&)> res_cb;
    std::function<void(security::SecurityObservation)> obs_cb;
    {
        std::lock_guard lk(cb_mtx_);
        res_cb = result_cb_;
        obs_cb = observation_cb_;
    }

    if (threat) {
        threats_found_.fetch_add(1);
        {
            std::lock_guard lk(mtx_);
            results_.push_back(result);
        }
        // res_cb is invoked after mtx_ is released: a callback that
        // re-enters this scanner (e.g. get_results()) must not self-deadlock.
        if (res_cb) res_cb(result);
    }

    // Escalate executables from Quick/Custom scans to ArtifactTrustEngine's
    // offline Authenticode check regardless of whether DeepScanner's own
    // (cheaper) checks already flagged this file -- an invalid PE header, for
    // instance, fails check_pe_header's own parse silently rather than being
    // reported, so gating on `threat` here would miss exactly the case
    // ArtifactTrustEngine is best at catching. Deep scans skip this: GCAD's
    // own from-scratch Authenticode chain verification (PKCS#7 parse, RSA
    // signature checks, PE hash, certificate chain walk) is real
    // cryptographic work per file, too slow to run across a system-wide walk
    // of potentially hundreds of thousands of files.
    if (obs_cb && (current_mode_ == ScanMode::QUICK || current_mode_ == ScanMode::CUSTOM)) {
        std::string ext = path.extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (ext == ".exe" || ext == ".dll" || ext == ".sys") {
            for (auto& observation : trust_engine_.inspect(path))
                obs_cb(observation);
        }
    }

    return threat;
}

bool DeepScanner::scan_buffer(const std::vector<uint8_t>& data, const std::string& origin,
                              ScanResult& out) {
    out.file_path = origin;
    ScanResult sig_res, sc_res, ent_res;
    sig_res.file_path = sc_res.file_path = ent_res.file_path = origin;

    if (check_signature_match(data, {}, sig_res)) { out = std::move(sig_res); return true; }
    if (check_shellcode_patterns(data, sc_res))    { out = std::move(sc_res);  return true; }
    if (check_entropy_anomaly(data, ent_res))      { out = std::move(ent_res); return true; }
    return false;
}

bool DeepScanner::scan_process_memory(uint32_t pid, const std::string& pname) {
    bool any = false;
    const size_t kMaxRegion = 16 * 1024 * 1024;
    const size_t kMaxPerProc = 64 * 1024 * 1024;
    size_t scanned = 0;

#ifdef GCAD_PLATFORM_WINDOWS
    HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProc) return false;

    MEMORY_BASIC_INFORMATION mbi{};
    uintptr_t addr = 0;
    while (!cancel_.load() && scanned < kMaxPerProc &&
           VirtualQueryEx(hProc, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(mbi)) == sizeof(mbi)) {
        uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        uintptr_t next = base + mbi.RegionSize;
        if (next <= addr) break; // guard against wrap
        addr = next;

        const DWORD exec_mask = PAGE_EXECUTE | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        if (mbi.State != MEM_COMMIT) continue;
        if ((mbi.Protect & exec_mask) == 0) continue;
        if (mbi.Protect & PAGE_GUARD) continue;

        size_t rsize = std::min<size_t>(mbi.RegionSize, kMaxRegion);
        std::vector<uint8_t> buf(rsize);
        SIZE_T got = 0;
        if (!ReadProcessMemory(hProc, mbi.BaseAddress, buf.data(), rsize, &got) || got == 0)
            continue;
        buf.resize(got);
        scanned += got;

        ScanResult r;
        if (scan_buffer(buf, "PID " + std::to_string(pid) + " (" + pname + ") @ 0x" +
                             std::format("{:x}", base), r)) {
            threats_found_.fetch_add(1);
            {
                std::lock_guard lk(mtx_);
                results_.push_back(r);
            }
            if (result_cb_) result_cb_(r);
            any = true;
        }
    }
    CloseHandle(hProc);
#else
    std::ifstream maps("/proc/" + std::to_string(pid) + "/maps");
    std::ifstream mem("/proc/" + std::to_string(pid) + "/mem", std::ios::binary);
    if (!maps || !mem) return false;
    std::string line;
    while (!cancel_.load() && scanned < kMaxPerProc && std::getline(maps, line)) {
        uintptr_t start = 0, end = 0;
        char perms[8] = {0};
        if (std::sscanf(line.c_str(), "%lx-%lx %7s", &start, &end, perms) != 3) continue;
        if (perms[2] != 'x' || end <= start) continue;
        size_t rsize = std::min<size_t>(end - start, kMaxRegion);
        std::vector<uint8_t> buf(rsize);
        mem.seekg(static_cast<std::streamoff>(start));
        mem.read(reinterpret_cast<char*>(buf.data()), rsize);
        auto got = static_cast<size_t>(mem.gcount());
        mem.clear();
        if (got == 0) continue;
        buf.resize(got);
        scanned += got;

        ScanResult r;
        if (scan_buffer(buf, "PID " + std::to_string(pid) + " (" + pname + ") @ 0x" +
                             std::format("{:x}", start), r)) {
            threats_found_.fetch_add(1);
            {
                std::lock_guard lk(mtx_);
                results_.push_back(r);
            }
            if (result_cb_) result_cb_(r);
            any = true;
        }
    }
#endif
    return any;
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

    // Deep PE static analysis (W^X violations, packers, entropy, dangerous APIs)
    auto report = pe_static_engine_.analyze_buffer(data.data(), data.size());
    if (report.is_valid_pe && report.assessed_level >= ThreatLevel::MEDIUM) {
        out.level = report.assessed_level;
        out.entropy = report.overall_entropy;
        if (report.is_packed) {
            out.category = ThreatCategory::MALWARE_PACKER;
            out.signature_name = "PE.Packer." + (report.detected_packer.empty() ? "Generic" : report.detected_packer);
            out.description = "Packed/Obfuscated PE binary (" + (report.detected_packer.empty() ? "High Entropy" : report.detected_packer) + ")";
        } else if (report.dangerous_api_score >= 100) {
            out.category = ThreatCategory::MEMORY_INJECTION;
            out.signature_name = "PE.DangerousAPIs";
            out.description = "PE with dangerous API cluster (Score: " + std::to_string(report.dangerous_api_score) + ")";
        } else {
            out.category = ThreatCategory::SUSPICIOUS_BINARY;
            out.signature_name = "PE.Anomaly";
            out.description = report.threat_reasons.empty() ? "PE static structural anomaly" : report.threat_reasons[0];
        }
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
    // Compilers (MSVC/GCC) use 16-byte NOP/INT3 padding for function alignment.
    // Real exploit NOP sleds span at least 32+ consecutive bytes.
    static const std::vector<uint8_t> nop_sled_32(32, 0x90);

    for (size_t i = 0; i + nop_sled_32.size() <= data.size(); ++i) {
        if (std::memcmp(data.data() + i, nop_sled_32.data(), nop_sled_32.size()) == 0) {
            size_t sled_end = i + nop_sled_32.size();
            while (sled_end < data.size() && data[sled_end] == 0x90)
                sled_end++;

            if (sled_end + 4 < data.size()) {
                uint8_t next = data[sled_end];
                if (next == 0xCC || next == 0xEB || next == 0xE8 || next == 0xE9 || next == 0x68 || next == 0x31) {
                    out.level = ThreatLevel::CRITICAL;
                    out.category = ThreatCategory::SHELLCODE;
                    out.description = "NOP sled (" + std::to_string(sled_end - i) +
                                      " bytes) followed by control transfer at offset " + std::to_string(i);
                    return true;
                }
            }
            i = sled_end;
        }
    }
    return false;
}

} // namespace gcad
