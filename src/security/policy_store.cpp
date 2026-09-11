#include "gcad/security/policy_store.hpp"

namespace gcad::security {

namespace {

constexpr int MAX_FINDING_WINDOW_MINUTES = 24 * 60;

} // namespace

LocalSecurityPolicy PolicyStore::load(const std::filesystem::path& path) {
    LocalSecurityPolicy policy{}; // safe defaults for a missing/unreadable file
    std::ifstream in(path);
    if (!in) return policy;

    std::vector<std::string> prefixes;
    bool prefixes_seen = false;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        const auto eq = line.find('=');
        if (eq == std::string::npos || eq == 0) continue; // corrupt line: skip, never fail the load
        const std::string key = line.substr(0, eq);
        const std::string value = line.substr(eq + 1);

        try {
            if (key == "critical_threshold") {
                const int v = std::stoi(value);
                if (v >= 0 && v <= 100) policy.critical_threshold = static_cast<uint8_t>(v);
            } else if (key == "finding_window_minutes") {
                const int v = std::stoi(value);
                if (v > 0 && v <= MAX_FINDING_WINDOW_MINUTES) policy.finding_window = std::chrono::minutes(v);
            } else if (key == "protected_path_prefix") {
                if (!value.empty()) {
                    prefixes.push_back(value);
                    prefixes_seen = true;
                }
            }
        } catch (...) {
            continue; // corrupt numeric field: keep this field's default, skip only this line
        }
    }

    if (prefixes_seen) policy.protected_path_prefixes = std::move(prefixes);
    return policy;
}

ErrorCode PolicyStore::save(const std::filesystem::path& path, const LocalSecurityPolicy& policy) {
    std::error_code ec;
    if (path.has_parent_path()) std::filesystem::create_directories(path.parent_path(), ec);

    std::ofstream out(path, std::ios::trunc);
    if (!out) return ErrorCode::ERR_SCAN_IO;

    out << "critical_threshold=" << static_cast<int>(policy.critical_threshold) << "\n";
    out << "finding_window_minutes=" << policy.finding_window.count() << "\n";
    for (const auto& prefix : policy.protected_path_prefixes)
        out << "protected_path_prefix=" << prefix << "\n";

    return out.good() ? ErrorCode::OK : ErrorCode::ERR_SCAN_IO;
}

} // namespace gcad::security
