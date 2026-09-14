#include "gcad/security/quarantine_executor.hpp"

namespace gcad::security {

namespace {

std::string ledger_line(const QuarantineRecord& record) {
    const auto epoch = std::chrono::duration_cast<std::chrono::seconds>(
        record.quarantined_at.time_since_epoch()).count();
    return std::to_string(record.id) + "|" + std::to_string(record.finding_id) + "|" +
           record.original_path + "|" + record.vault_path + "|" + record.sha256_at_quarantine + "|" +
           std::to_string(epoch) + "|" + (record.restored ? "1" : "0") + "|" +
           (record.shredded ? "1" : "0");
}

// '|' is invalid in a Windows path component; refusing it here keeps every
// ledger line unambiguous to split without a quoting scheme.
bool has_unsafe_delimiter(const std::string& value) {
    return value.find('|') != std::string::npos || value.find('\n') != std::string::npos;
}

} // namespace

QuarantineExecutor::QuarantineExecutor(std::filesystem::path vault_dir, LocalSecurityPolicy policy)
    : vault_dir_(std::move(vault_dir)), ledger_path_(vault_dir_ / "ledger.txt"), policy_(std::move(policy)) {
    std::error_code ec;
    std::filesystem::create_directories(vault_dir_, ec);
    std::lock_guard lk(mtx_);
    load_ledger_locked();
}

void QuarantineExecutor::load_ledger_locked() {
    std::ifstream in(ledger_path_);
    if (!in) return;

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        std::vector<std::string> fields;
        size_t start = 0;
        for (;;) {
            const size_t pos = line.find('|', start);
            fields.push_back(line.substr(start, pos == std::string::npos ? std::string::npos : pos - start));
            if (pos == std::string::npos) break;
            start = pos + 1;
        }
        if (fields.size() != 7 && fields.size() != 8) continue; // corrupt line: skip, never abort the whole ledger

        try {
            QuarantineRecord record{};
            record.id = std::stoull(fields[0]);
            record.finding_id = std::stoull(fields[1]);
            record.original_path = fields[2];
            record.vault_path = fields[3];
            record.sha256_at_quarantine = fields[4];
            record.quarantined_at = std::chrono::system_clock::time_point(
                std::chrono::seconds(std::stoll(fields[5])));
            record.restored = fields[6] == "1";
            if (fields.size() >= 8) {
                record.shredded = fields[7] == "1";
            }
            ledger_.push_back(std::move(record));
            if (ledger_.back().id >= next_id_) next_id_ = ledger_.back().id + 1;
        } catch (...) {
            continue; // corrupt numeric field: skip only this line
        }
    }
}

void QuarantineExecutor::append_ledger_locked(const QuarantineRecord& record) {
    std::ofstream out(ledger_path_, std::ios::app);
    if (!out) { GCAD_LOG(ERR, "QuarantineExecutor: failed to append ledger entry"); return; }
    out << ledger_line(record) << "\n";
}

void QuarantineExecutor::rewrite_ledger_locked() {
    std::filesystem::path tmp_path = ledger_path_;
    tmp_path += ".tmp";
    {
        std::ofstream out(tmp_path, std::ios::binary | std::ios::trunc);
        if (!out) { GCAD_LOG(ERR, "QuarantineExecutor: failed to open temp ledger"); return; }
        for (const auto& record : ledger_) out << ledger_line(record) << "\n";
        out.flush();
    }
    std::error_code ec;
    std::filesystem::rename(tmp_path, ledger_path_, ec);
    if (ec) {
        std::filesystem::copy_file(tmp_path, ledger_path_,
                                   std::filesystem::copy_options::overwrite_existing, ec);
        std::filesystem::remove(tmp_path, ec);
    }
}

ErrorCode QuarantineExecutor::quarantine(const RemediationCandidate& candidate, QuarantineRecord& out) {
    if (candidate.approval_state != CandidateApprovalState::APPROVED) return ErrorCode::ERR_QUARANTINE_DENIED;
    if (candidate.target_path.empty()) return ErrorCode::ERR_QUARANTINE_DENIED;
    if (has_unsafe_delimiter(candidate.target_path)) return ErrorCode::ERR_QUARANTINE_DENIED;

    // Cheap, I/O-free checks first: a protected path is refused before ever
    // touching the filesystem, so this rule applies even to a path that does
    // not exist (or is not ours to probe).
    if (PolicyEngine::is_protected_path(candidate.target_path, policy_))
        return ErrorCode::ERR_QUARANTINE_DENIED;

    const std::filesystem::path target(candidate.target_path);
    std::error_code ec;

    if (std::filesystem::is_symlink(target, ec) || ec) return ErrorCode::ERR_QUARANTINE_DENIED;
    ec.clear();
    if (!std::filesystem::is_regular_file(target, ec) || ec) return ErrorCode::ERR_QUARANTINE_DENIED;
    ec.clear();

    const auto size = std::filesystem::file_size(target, ec);
    if (ec || size == 0 || size > MAX_QUARANTINE_BYTES) return ErrorCode::ERR_QUARANTINE_DENIED;

    const std::string current_hash = SHA256::hash_file(target);
    if (current_hash.empty()) return ErrorCode::ERR_QUARANTINE_DENIED;
    if (!candidate.expected_sha256.empty() && current_hash != candidate.expected_sha256)
        return ErrorCode::ERR_QUARANTINE_DENIED; // file changed since detection: stale evidence

    std::lock_guard lk(mtx_);
    if (ledger_.size() >= MAX_LEDGER_RECORDS) return ErrorCode::ERR_QUARANTINE_FULL;

    const uint64_t id = next_id_++;
    const std::filesystem::path vault_path = vault_dir_ / ("q_" + std::to_string(id) + ".gcadq");

    ec.clear();
    std::filesystem::rename(target, vault_path, ec);
    if (ec) {
        // Cross-volume rename fails on Windows; fall back to copy+remove so a
        // quarantine target on a different drive than the vault still works.
        ec.clear();
        std::filesystem::copy_file(target, vault_path, std::filesystem::copy_options::none, ec);
        if (ec) return ErrorCode::ERR_QUARANTINE_DENIED;
        ec.clear();
        std::filesystem::remove(target, ec);
        if (ec) {
            // Copied but could not remove the original: undo the copy rather
            // than leaving two live copies of a quarantined artifact.
            std::error_code cleanup_ec;
            std::filesystem::remove(vault_path, cleanup_ec);
            return ErrorCode::ERR_QUARANTINE_DENIED;
        }
    }

    QuarantineRecord record{};
    record.id = id;
    record.finding_id = candidate.finding_id;
    record.original_path = candidate.target_path;
    record.vault_path = vault_path.generic_string();
    record.sha256_at_quarantine = current_hash;
    record.quarantined_at = std::chrono::system_clock::now();
    record.restored = false;

    ledger_.push_back(record);
    append_ledger_locked(record);
    out = record;
    return ErrorCode::OK;
}

ErrorCode QuarantineExecutor::restore(uint64_t record_id) {
    std::lock_guard lk(mtx_);
    for (auto& record : ledger_) {
        if (record.id != record_id) continue;
        if (record.shredded) return ErrorCode::ERR_ROLLBACK_FAIL; // shredded files cannot be restored
        if (record.restored) return ErrorCode::OK; // idempotent

        std::error_code ec;
        const std::filesystem::path original(record.original_path);
        if (std::filesystem::exists(original, ec))
            return ErrorCode::ERR_ROLLBACK_FAIL; // refuse to overwrite whatever occupies it now

        const std::filesystem::path vault_path(record.vault_path);
        ec.clear();
        if (!std::filesystem::exists(vault_path, ec)) return ErrorCode::ERR_ROLLBACK_FAIL;

        if (original.has_parent_path()) {
            ec.clear();
            std::filesystem::create_directories(original.parent_path(), ec);
        }

        ec.clear();
        std::filesystem::rename(vault_path, original, ec);
        if (ec) {
            ec.clear();
            std::filesystem::copy_file(vault_path, original, std::filesystem::copy_options::none, ec);
            if (ec) return ErrorCode::ERR_ROLLBACK_FAIL;
            ec.clear();
            std::filesystem::remove(vault_path, ec);
        }

        record.restored = true;
        rewrite_ledger_locked();
        return ErrorCode::OK;
    }
    return ErrorCode::ERR_NOT_FOUND;
}

ErrorCode QuarantineExecutor::shred(uint64_t record_id) {
    std::lock_guard lk(mtx_);
    for (auto& record : ledger_) {
        if (record.id != record_id) continue;
        if (record.shredded) return ErrorCode::OK; // idempotent
        if (record.restored) return ErrorCode::ERR_NOT_FOUND; // file already restored out of vault

        const std::filesystem::path vault_path(record.vault_path);
        std::error_code ec;
        if (std::filesystem::exists(vault_path, ec)) {
            const auto size = std::filesystem::file_size(vault_path, ec);
            if (!ec && size > 0) {
                // Secure zero-overwrite shredding (0x00 pattern)
                std::ofstream out(vault_path, std::ios::binary | std::ios::in | std::ios::out);
                if (out) {
                    constexpr size_t CHUNK_SIZE = 64 * 1024;
                    std::vector<char> zeros(CHUNK_SIZE, 0);
                    uintmax_t remaining = size;
                    while (remaining > 0 && out) {
                        const size_t to_write = static_cast<size_t>(std::min<uintmax_t>(remaining, CHUNK_SIZE));
                        out.write(zeros.data(), static_cast<std::streamsize>(to_write));
                        remaining -= to_write;
                    }
                    out.flush();
                }
            }
            ec.clear();
            std::filesystem::remove(vault_path, ec);
        }

        record.shredded = true;
        rewrite_ledger_locked();
        return ErrorCode::OK;
    }
    return ErrorCode::ERR_NOT_FOUND;
}

std::vector<QuarantineRecord> QuarantineExecutor::records(size_t count) const {
    std::lock_guard lk(mtx_);
    const size_t start = ledger_.size() > count ? ledger_.size() - count : 0;
    return {ledger_.begin() + static_cast<std::ptrdiff_t>(start), ledger_.end()};
}

} // namespace gcad::security
