#include "gcad/common.hpp"
#include "gcad/security/policy_store.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

namespace {

std::filesystem::path temp_policy_path(const char* name) {
    return std::filesystem::temp_directory_path() / name;
}

} // namespace

void register_policy_store_tests() {
    register_test("policy_store_returns_defaults_for_missing_file", [] {
        const auto path = temp_policy_path("gcad-policy-missing.txt");
        std::error_code ec;
        std::filesystem::remove(path, ec);
        const auto policy = gcad::security::PolicyStore::load(path);
        const gcad::security::LocalSecurityPolicy defaults{};
        return policy.critical_threshold == defaults.critical_threshold &&
               policy.finding_window == defaults.finding_window &&
               policy.protected_path_prefixes == defaults.protected_path_prefixes;
    });

    register_test("policy_store_round_trips_custom_values", [] {
        const auto path = temp_policy_path("gcad-policy-roundtrip.txt");
        gcad::security::LocalSecurityPolicy policy{};
        policy.critical_threshold = 75;
        policy.finding_window = std::chrono::minutes{12};
        policy.protected_path_prefixes = {"c:/custom/protected/", "c:/other/"};

        if (gcad::security::PolicyStore::save(path, policy) != gcad::ErrorCode::OK) return false;
        const auto loaded = gcad::security::PolicyStore::load(path);
        std::error_code ec;
        std::filesystem::remove(path, ec);

        return loaded.critical_threshold == 75 &&
               loaded.finding_window == std::chrono::minutes{12} &&
               loaded.protected_path_prefixes == policy.protected_path_prefixes;
    });

    register_test("policy_store_rejects_out_of_range_threshold_per_field", [] {
        const auto path = temp_policy_path("gcad-policy-badthreshold.txt");
        std::ofstream out(path, std::ios::trunc);
        out << "critical_threshold=500\n";
        out << "finding_window_minutes=10\n";
        out.close();

        const auto loaded = gcad::security::PolicyStore::load(path);
        std::error_code ec;
        std::filesystem::remove(path, ec);

        const gcad::security::LocalSecurityPolicy defaults{};
        return loaded.critical_threshold == defaults.critical_threshold &&
               loaded.finding_window == std::chrono::minutes{10};
    });

    register_test("policy_store_ignores_corrupt_lines_without_failing", [] {
        const auto path = temp_policy_path("gcad-policy-corrupt.txt");
        std::ofstream out(path, std::ios::trunc);
        out << "not a valid line at all\n";
        out << "critical_threshold=notanumber\n";
        out << "=noKey\n";
        out << "critical_threshold=80\n";
        out.close();

        const auto loaded = gcad::security::PolicyStore::load(path);
        std::error_code ec;
        std::filesystem::remove(path, ec);
        return loaded.critical_threshold == 80;
    });

    register_test("policy_store_keeps_default_prefixes_when_file_omits_them", [] {
        const auto path = temp_policy_path("gcad-policy-noprefixes.txt");
        std::ofstream out(path, std::ios::trunc);
        out << "critical_threshold=95\n";
        out.close();

        const auto loaded = gcad::security::PolicyStore::load(path);
        std::error_code ec;
        std::filesystem::remove(path, ec);

        const gcad::security::LocalSecurityPolicy defaults{};
        return loaded.critical_threshold == 95 &&
               loaded.protected_path_prefixes == defaults.protected_path_prefixes;
    });
}
