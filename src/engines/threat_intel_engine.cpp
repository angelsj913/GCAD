#include "gcad/engines/threat_intel_engine.hpp"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <cctype>

namespace gcad {

ThreatIntelEngine::ThreatIntelEngine() = default;
ThreatIntelEngine::~ThreatIntelEngine() { stop(); }

ErrorCode ThreatIntelEngine::start() {
    if (running_.load()) return ErrorCode::OK;
    install_default_iocs();
    running_.store(true);
    monitor_thread_ = std::thread(&ThreatIntelEngine::monitor_loop, this);
    GCAD_LOG(INFO, "ThreatIntel engine started, " + std::to_string(iocs_.size()) + " IOCs loaded");
    return ErrorCode::OK;
}

ErrorCode ThreatIntelEngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    return ErrorCode::OK;
}

EngineStatus ThreatIntelEngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    return s;
}

void ThreatIntelEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

void ThreatIntelEngine::on_observation(std::function<void(security::SecurityObservation)> cb) {
    std::lock_guard lk(mtx_);
    observation_cb_ = std::move(cb);
}

uint64_t ThreatIntelEngine::add_ioc(IocEntry entry) {
    std::lock_guard lk(mtx_);
    entry.id = next_id_.fetch_add(1);
    if (entry.added_at == std::chrono::system_clock::time_point{})
        entry.added_at = std::chrono::system_clock::now();

    if (entry.type == IocType::SHA256_HASH || entry.type == IocType::MD5_HASH)
        entry.value = normalize_hash(entry.value);
    else if (entry.type == IocType::DOMAIN)
        entry.value = normalize_domain(entry.value);

    iocs_.push_back(entry);
    rebuild_indices();
    return entry.id;
}

bool ThreatIntelEngine::remove_ioc(uint64_t id) {
    std::lock_guard lk(mtx_);
    auto it = std::find_if(iocs_.begin(), iocs_.end(),
                           [id](auto& e) { return e.id == id; });
    if (it == iocs_.end()) return false;
    iocs_.erase(it);
    rebuild_indices();
    return true;
}

size_t ThreatIntelEngine::load_from_file(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f) return 0;

    size_t count = 0;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;

        std::istringstream ss(line);
        std::string type_str, value, severity_str, source, desc;
        if (!std::getline(ss, type_str, '|')) continue;
        if (!std::getline(ss, value, '|')) continue;
        std::getline(ss, severity_str, '|');
        std::getline(ss, source, '|');
        std::getline(ss, desc, '|');

        IocEntry e;
        if (type_str == "sha256") e.type = IocType::SHA256_HASH;
        else if (type_str == "md5") e.type = IocType::MD5_HASH;
        else if (type_str == "ip") e.type = IocType::IPV4_ADDRESS;
        else if (type_str == "domain") e.type = IocType::DOMAIN;
        else if (type_str == "url") e.type = IocType::URL;
        else if (type_str == "filename") e.type = IocType::FILE_NAME;
        else continue;

        e.value = value;
        if (severity_str == "critical") e.severity = ThreatLevel::CRITICAL;
        else if (severity_str == "high") e.severity = ThreatLevel::HIGH;
        else if (severity_str == "medium") e.severity = ThreatLevel::MEDIUM;
        else if (severity_str == "low") e.severity = ThreatLevel::LOW;
        e.source = source;
        e.description = desc;

        add_ioc(std::move(e));
        ++count;
    }
    return count;
}

void ThreatIntelEngine::clear_iocs() {
    std::lock_guard lk(mtx_);
    iocs_.clear();
    hash_index_.clear();
    ip_index_.clear();
    domain_index_.clear();
}

size_t ThreatIntelEngine::import_iocs_from_string(const std::string& content, const std::string& default_source) {
    std::istringstream stream(content);
    std::string line;
    size_t count = 0;

    while (std::getline(stream, line)) {
        auto start = line.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) continue;
        auto end = line.find_last_not_of(" \t\r\n");
        std::string trimmed = line.substr(start, end - start + 1);
        if (trimmed.empty() || trimmed[0] == '#') continue;

        std::istringstream ss(trimmed);
        std::string type_str, value, severity_str, source, desc;
        if (!std::getline(ss, type_str, '|')) continue;
        if (!std::getline(ss, value, '|')) continue;
        std::getline(ss, severity_str, '|');
        std::getline(ss, source, '|');
        std::getline(ss, desc, '|');

        IocEntry e;
        if (type_str == "sha256") e.type = IocType::SHA256_HASH;
        else if (type_str == "md5") e.type = IocType::MD5_HASH;
        else if (type_str == "ip") e.type = IocType::IPV4_ADDRESS;
        else if (type_str == "domain") e.type = IocType::DOMAIN;
        else if (type_str == "url") e.type = IocType::URL;
        else if (type_str == "filename") e.type = IocType::FILE_NAME;
        else continue;

        e.value = value;
        if (severity_str == "critical") e.severity = ThreatLevel::CRITICAL;
        else if (severity_str == "high") e.severity = ThreatLevel::HIGH;
        else if (severity_str == "medium") e.severity = ThreatLevel::MEDIUM;
        else if (severity_str == "low") e.severity = ThreatLevel::LOW;
        else e.severity = ThreatLevel::HIGH;

        e.source = source.empty() ? default_source : source;
        e.description = desc;

        add_ioc(std::move(e));
        ++count;
    }
    return count;
}

size_t ThreatIntelEngine::reload_from_directory(const std::filesystem::path& dir_path) {
    std::error_code ec;
    if (!std::filesystem::exists(dir_path, ec) || !std::filesystem::is_directory(dir_path, ec)) return 0;

    size_t loaded = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir_path, ec)) {
        if (!entry.is_regular_file(ec)) continue;
        const auto ext = entry.path().extension().string();
        if (ext == ".ioc" || ext == ".txt" || ext == ".csv") {
            loaded += load_from_file(entry.path());
        }
    }
    return loaded;
}

size_t ThreatIntelEngine::reload_all(const std::filesystem::path& dir_path) {
    clear_iocs();
    install_default_iocs();
    if (!dir_path.empty()) {
        reload_from_directory(dir_path);
    }
    return ioc_count();
}

size_t ThreatIntelEngine::save_to_file(const std::filesystem::path& path) const {
    std::lock_guard lk(mtx_);
    std::ofstream f(path, std::ios::trunc);
    if (!f) return 0;

    f << "# GCAD Threat Intelligence IOC Database\n";
    f << "# Format: type|value|severity|source|description\n";

    size_t count = 0;
    for (auto& e : iocs_) {
        if (!e.active) continue;
        const char* type_str = "sha256";
        switch (e.type) {
            case IocType::SHA256_HASH:  type_str = "sha256"; break;
            case IocType::MD5_HASH:     type_str = "md5"; break;
            case IocType::IPV4_ADDRESS: type_str = "ip"; break;
            case IocType::DOMAIN:       type_str = "domain"; break;
            case IocType::URL:          type_str = "url"; break;
            case IocType::FILE_NAME:    type_str = "filename"; break;
        }
        const char* sev = "high";
        switch (e.severity) {
            case ThreatLevel::CRITICAL: sev = "critical"; break;
            case ThreatLevel::HIGH:     sev = "high"; break;
            case ThreatLevel::MEDIUM:   sev = "medium"; break;
            case ThreatLevel::LOW:      sev = "low"; break;
            default: break;
        }
        f << type_str << "|" << e.value << "|" << sev << "|" << e.source << "|" << e.description << "\n";
        ++count;
    }
    return count;
}

bool ThreatIntelEngine::check_hash(const std::string& hash) const {
    std::lock_guard lk(mtx_);
    return hash_index_.count(normalize_hash(hash)) > 0;
}

bool ThreatIntelEngine::check_ip(const std::string& ip) const {
    std::lock_guard lk(mtx_);
    return ip_index_.count(ip) > 0;
}

bool ThreatIntelEngine::check_domain(const std::string& domain) const {
    std::lock_guard lk(mtx_);
    return domain_index_.count(normalize_domain(domain)) > 0;
}

std::vector<IocMatch> ThreatIntelEngine::lookup(const std::string& value) const {
    std::lock_guard lk(mtx_);
    std::vector<IocMatch> results;
    auto norm_hash = normalize_hash(value);
    auto norm_domain = normalize_domain(value);

    for (auto& e : iocs_) {
        if (!e.active) continue;
        bool match = false;
        if ((e.type == IocType::SHA256_HASH || e.type == IocType::MD5_HASH) && e.value == norm_hash)
            match = true;
        else if (e.type == IocType::IPV4_ADDRESS && e.value == value)
            match = true;
        else if (e.type == IocType::DOMAIN && e.value == norm_domain)
            match = true;
        else if (e.type == IocType::URL && e.value == value)
            match = true;
        else if (e.type == IocType::FILE_NAME && e.value == value)
            match = true;

        if (match) {
            IocMatch m;
            m.ioc = e;
            m.matched_against = value;
            m.matched_at = std::chrono::system_clock::now();
            results.push_back(std::move(m));
        }
    }
    return results;
}

std::vector<IocMatch> ThreatIntelEngine::recent_matches(size_t n) const {
    std::lock_guard lk(mtx_);
    size_t count = std::min(n, match_log_.size());
    return {match_log_.end() - static_cast<ptrdiff_t>(count), match_log_.end()};
}

std::vector<IocEntry> ThreatIntelEngine::all_iocs() const {
    std::lock_guard lk(mtx_);
    return iocs_;
}

size_t ThreatIntelEngine::ioc_count() const {
    std::lock_guard lk(mtx_);
    return iocs_.size();
}

std::string ThreatIntelEngine::normalize_domain(std::string_view domain) {
    std::string result(domain);
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    while (!result.empty() && result.back() == '.') result.pop_back();
    return result;
}

std::string ThreatIntelEngine::normalize_hash(std::string_view hash) {
    std::string result(hash);
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

IocType ThreatIntelEngine::detect_type(std::string_view value) {
    if (value.size() == 64) {
        bool all_hex = true;
        for (char c : value) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) { all_hex = false; break; }
        }
        if (all_hex) return IocType::SHA256_HASH;
    }
    if (value.size() == 32) {
        bool all_hex = true;
        for (char c : value) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) { all_hex = false; break; }
        }
        if (all_hex) return IocType::MD5_HASH;
    }

    int dots = 0;
    bool all_digits_dots = true;
    for (char c : value) {
        if (c == '.') ++dots;
        else if (!std::isdigit(static_cast<unsigned char>(c))) all_digits_dots = false;
    }
    if (dots == 3 && all_digits_dots) return IocType::IPV4_ADDRESS;

    if (value.starts_with("http://") || value.starts_with("https://"))
        return IocType::URL;

    if (dots >= 1) return IocType::DOMAIN;

    return IocType::FILE_NAME;
}

void ThreatIntelEngine::rebuild_indices() {
    hash_index_.clear();
    ip_index_.clear();
    domain_index_.clear();
    for (auto& e : iocs_) {
        if (!e.active) continue;
        switch (e.type) {
            case IocType::SHA256_HASH:
            case IocType::MD5_HASH:
                hash_index_.insert(e.value);
                break;
            case IocType::IPV4_ADDRESS:
                ip_index_.insert(e.value);
                break;
            case IocType::DOMAIN:
                domain_index_.insert(e.value);
                break;
            default: break;
        }
    }
}

void ThreatIntelEngine::monitor_loop() {
    while (running_.load()) {
        for (int slept = 0; slept < 10000 && running_.load(); slept += 100)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!running_.load()) break;
        events_processed_.fetch_add(1);
    }
}

void ThreatIntelEngine::record_match(const IocEntry& ioc, const std::string& against,
                                      const std::string& ctx) {
    IocMatch m;
    m.ioc = ioc;
    m.matched_against = against;
    m.context = ctx;
    m.matched_at = std::chrono::system_clock::now();

    std::lock_guard lk(mtx_);
    match_log_.push_back(std::move(m));
    while (match_log_.size() > MAX_MATCHES) match_log_.pop_front();
}

void ThreatIntelEngine::emit_threat(ThreatCategory cat, const std::string& desc) {
    threats_detected_.fetch_add(1);
    std::function<void(ThreatEvent)> cb;
    {
        std::lock_guard lk(mtx_);
        cb = threat_cb_;
    }
    if (cb) {
        ThreatEvent ev{};
        ev.level = ThreatLevel::HIGH;
        ev.category = cat;
        ev.description = desc;
        ev.timestamp = std::chrono::system_clock::now();
        cb(std::move(ev));
    }
}

void ThreatIntelEngine::emit_observation(security::ObservationKind kind, ThreatLevel level,
                                          double confidence, const std::string& evidence) {
    std::function<void(security::SecurityObservation)> cb;
    {
        std::lock_guard lk(mtx_);
        cb = observation_cb_;
    }
    if (cb) {
        security::SecurityObservation obs{};
        obs.source_id = "threat-intel";
        obs.kind = kind;
        obs.timestamp = std::chrono::system_clock::now();
        obs.suggested_level = level;
        obs.confidence = confidence;
        obs.deterministic = true;
        obs.evidence = evidence;
        cb(std::move(obs));
    }
}

void ThreatIntelEngine::install_default_iocs() {
    std::lock_guard lk(mtx_);
    if (!iocs_.empty()) return;

    auto add = [this](IocType type, const char* value, ThreatLevel sev,
                      const char* src, const char* desc) {
        IocEntry e;
        e.id = next_id_.fetch_add(1);
        e.type = type;
        e.value = value;
        e.severity = sev;
        e.source = src;
        e.description = desc;
        e.added_at = std::chrono::system_clock::now();
        iocs_.push_back(std::move(e));
    };

    add(IocType::DOMAIN, "malware-c2.example.com", ThreatLevel::CRITICAL, "GCAD-default", "Known C2 domain");
    add(IocType::DOMAIN, "phishing-site.example.net", ThreatLevel::HIGH, "GCAD-default", "Known phishing domain");
    add(IocType::DOMAIN, "cryptominer-pool.example.org", ThreatLevel::HIGH, "GCAD-default", "Cryptominer pool");
    add(IocType::IPV4_ADDRESS, "198.51.100.1", ThreatLevel::CRITICAL, "GCAD-default", "Known C2 server");
    add(IocType::IPV4_ADDRESS, "203.0.113.50", ThreatLevel::HIGH, "GCAD-default", "Known scanner");
    add(IocType::SHA256_HASH, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ThreatLevel::LOW, "GCAD-default", "Empty file hash (suspicious if unexpected)");
    add(IocType::FILE_NAME, "mimikatz.exe", ThreatLevel::CRITICAL, "GCAD-default", "Credential dumping tool");
    add(IocType::FILE_NAME, "lazagne.exe", ThreatLevel::HIGH, "GCAD-default", "Password recovery tool");
    add(IocType::FILE_NAME, "psexec.exe", ThreatLevel::MEDIUM, "GCAD-default", "Remote execution tool");

    rebuild_indices();
}

} // namespace gcad
