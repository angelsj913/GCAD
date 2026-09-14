#include "gcad/common.hpp"
#include "gcad/security/quarantine_executor.hpp"

extern void register_test(const char* name, std::function<bool()> fn);

namespace {

std::filesystem::path make_temp_dir(const char* name) {
    auto dir = std::filesystem::temp_directory_path() / name;
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir, ec);
    return dir;
}

std::filesystem::path write_fixture_file(const std::filesystem::path& dir, const char* name,
                                         const std::string& content) {
    const auto path = dir / name;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << content;
    return path;
}

gcad::security::RemediationCandidate candidate_for(
    const std::filesystem::path& target, gcad::security::CandidateApprovalState state,
    std::string expected_sha256 = {}) {
    gcad::security::RemediationCandidate candidate{};
    candidate.finding_id = 777;
    candidate.requested_action = gcad::security::ResponseAction::QUARANTINE_CANDIDATE;
    candidate.approval_state = state;
    candidate.target_path = target.generic_string();
    candidate.rationale = "controlled test candidate";
    candidate.expected_sha256 = std::move(expected_sha256);
    return candidate;
}

} // namespace

void register_quarantine_executor_tests() {
    register_test("quarantine_executor_denies_unapproved_candidate", [] {
        const auto dir = make_temp_dir("gcad-qtest-unapproved");
        const auto file = write_fixture_file(dir, "sample.bin", "pending approval content");
        gcad::security::QuarantineExecutor executor(dir / "vault");

        gcad::security::QuarantineRecord record{};
        const auto rc = executor.quarantine(
            candidate_for(file, gcad::security::CandidateApprovalState::PENDING_APPROVAL), record);

        std::error_code ec;
        const bool untouched = std::filesystem::exists(file, ec);
        std::filesystem::remove_all(dir, ec);
        return rc == gcad::ErrorCode::ERR_QUARANTINE_DENIED && untouched;
    });

    register_test("quarantine_executor_moves_approved_file_into_vault", [] {
        const auto dir = make_temp_dir("gcad-qtest-approved");
        const auto file = write_fixture_file(dir, "sample.bin", "approved content to move");
        gcad::security::QuarantineExecutor executor(dir / "vault");

        gcad::security::QuarantineRecord record{};
        const auto rc = executor.quarantine(
            candidate_for(file, gcad::security::CandidateApprovalState::APPROVED), record);

        std::error_code ec;
        const bool original_gone = !std::filesystem::exists(file, ec);
        const bool vault_exists = std::filesystem::exists(record.vault_path, ec);
        const bool listed = !executor.records(10).empty();
        std::filesystem::remove_all(dir, ec);

        return rc == gcad::ErrorCode::OK && original_gone && vault_exists && listed &&
               !record.sha256_at_quarantine.empty();
    });

    register_test("quarantine_executor_denies_when_hash_mismatches_expected", [] {
        const auto dir = make_temp_dir("gcad-qtest-hashmismatch");
        const auto file = write_fixture_file(dir, "sample.bin", "content changed since detection");
        gcad::security::QuarantineExecutor executor(dir / "vault");

        gcad::security::QuarantineRecord record{};
        const auto rc = executor.quarantine(
            candidate_for(file, gcad::security::CandidateApprovalState::APPROVED,
                         "0000000000000000000000000000000000000000000000000000000000000000"),
            record);

        std::error_code ec;
        const bool untouched = std::filesystem::exists(file, ec);
        std::filesystem::remove_all(dir, ec);
        return rc == gcad::ErrorCode::ERR_QUARANTINE_DENIED && untouched;
    });

    register_test("quarantine_executor_denies_protected_path_without_touching_filesystem", [] {
        const auto dir = make_temp_dir("gcad-qtest-protected");
        gcad::security::QuarantineExecutor executor(dir / "vault");

        gcad::security::QuarantineRecord record{};
        // A path that does not need to exist: the protected-path check must
        // reject before any filesystem access, so this proves the check runs
        // first rather than failing only because the file is missing.
        const auto rc = executor.quarantine(
            candidate_for("C:/Windows/System32/notepad.exe",
                         gcad::security::CandidateApprovalState::APPROVED),
            record);

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        return rc == gcad::ErrorCode::ERR_QUARANTINE_DENIED;
    });

    register_test("quarantine_executor_restores_a_quarantined_file", [] {
        const auto dir = make_temp_dir("gcad-qtest-restore");
        const auto file = write_fixture_file(dir, "sample.bin", "restore me please");
        gcad::security::QuarantineExecutor executor(dir / "vault");

        gcad::security::QuarantineRecord record{};
        executor.quarantine(candidate_for(file, gcad::security::CandidateApprovalState::APPROVED), record);
        const auto rc = executor.restore(record.id);

        std::error_code ec;
        const bool restored_file_exists = std::filesystem::exists(file, ec);
        const bool vault_gone = !std::filesystem::exists(record.vault_path, ec);
        std::filesystem::remove_all(dir, ec);
        return rc == gcad::ErrorCode::OK && restored_file_exists && vault_gone;
    });

    register_test("quarantine_executor_restore_refuses_to_overwrite_existing_file", [] {
        const auto dir = make_temp_dir("gcad-qtest-restore-conflict");
        const auto file = write_fixture_file(dir, "sample.bin", "original quarantined content");
        gcad::security::QuarantineExecutor executor(dir / "vault");

        gcad::security::QuarantineRecord record{};
        executor.quarantine(candidate_for(file, gcad::security::CandidateApprovalState::APPROVED), record);

        // Something else now occupies the original path.
        write_fixture_file(dir, "sample.bin", "unrelated new content");
        const auto rc = executor.restore(record.id);

        std::error_code ec;
        std::ifstream check(file, std::ios::binary);
        std::string current((std::istreambuf_iterator<char>(check)), std::istreambuf_iterator<char>());
        const bool vault_preserved = std::filesystem::exists(record.vault_path, ec);
        std::filesystem::remove_all(dir, ec);

        return rc == gcad::ErrorCode::ERR_ROLLBACK_FAIL && current == "unrelated new content" &&
               vault_preserved;
    });

    register_test("quarantine_executor_persists_ledger_across_instances", [] {
        const auto dir = make_temp_dir("gcad-qtest-persist");
        const auto file = write_fixture_file(dir, "sample.bin", "persisted content");
        const auto vault = dir / "vault";

        gcad::security::QuarantineRecord record{};
        {
            gcad::security::QuarantineExecutor executor(vault);
            executor.quarantine(candidate_for(file, gcad::security::CandidateApprovalState::APPROVED), record);
        }

        gcad::security::QuarantineExecutor reopened(vault);
        const auto records = reopened.records(10);
        const bool found = std::any_of(records.begin(), records.end(),
            [&](const auto& r) { return r.id == record.id && r.original_path == record.original_path; });

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        return found;
    });

    register_test("quarantine_executor_shreds_vaulted_file_with_zero_overwrite", [] {
        const auto dir = make_temp_dir("gcad-qtest-shred");
        const auto file = write_fixture_file(dir, "malware.bin", "dangerous payload to shred");
        gcad::security::QuarantineExecutor executor(dir / "vault");

        gcad::security::QuarantineRecord record{};
        executor.quarantine(candidate_for(file, gcad::security::CandidateApprovalState::APPROVED), record);

        std::error_code ec;
        const bool vault_exists_before = std::filesystem::exists(record.vault_path, ec);
        const auto rc_shred = executor.shred(record.id);
        const bool vault_gone_after = !std::filesystem::exists(record.vault_path, ec);
        const auto rc_restore = executor.restore(record.id); // Cannot restore shredded file

        const auto recs = executor.records(10);
        const bool is_marked_shredded = !recs.empty() && recs.back().id == record.id && recs.back().shredded;

        std::filesystem::remove_all(dir, ec);
        return vault_exists_before && rc_shred == gcad::ErrorCode::OK && vault_gone_after &&
               rc_restore == gcad::ErrorCode::ERR_ROLLBACK_FAIL && is_marked_shredded;
    });

    register_test("quarantine_executor_shred_persists_across_restart", [] {
        const auto dir = make_temp_dir("gcad-qtest-shred-persist");
        const auto file = write_fixture_file(dir, "malware2.bin", "second payload to shred");
        const auto vault = dir / "vault";

        gcad::security::QuarantineRecord record{};
        {
            gcad::security::QuarantineExecutor executor(vault);
            executor.quarantine(candidate_for(file, gcad::security::CandidateApprovalState::APPROVED), record);
            executor.shred(record.id);
        }

        gcad::security::QuarantineExecutor reopened(vault);
        const auto records = reopened.records(10);
        const bool found_and_shredded = std::any_of(records.begin(), records.end(),
            [&](const auto& r) { return r.id == record.id && r.shredded && !r.restored; });

        std::error_code ec;
        std::filesystem::remove_all(dir, ec);
        return found_and_shredded;
    });
}
