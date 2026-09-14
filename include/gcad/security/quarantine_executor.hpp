#pragma once

#include "policy.hpp"
#include <deque>

namespace gcad::security {

struct QuarantineRecord {
    uint64_t                              id{0};
    uint64_t                              finding_id{0};
    std::string                           original_path;
    std::string                           vault_path;
    std::string                           sha256_at_quarantine;
    std::chrono::system_clock::time_point quarantined_at{};
    bool                                  restored{false};
    bool                                  shredded{false};
};

// Moves an explicitly APPROVED RemediationCandidate's target file into a local
// vault directory, and can move it back or securely shred it (0x00 zero-overwrite).
// This is the only component in GCAD that touches a detected file's location on
// disk, and it does so only when given a candidate whose approval_state is already
// APPROVED -- it never changes that state itself and never acts on PENDING_APPROVAL
// or REJECTED.
//
// Every call re-validates at execution time rather than trusting the
// candidate blindly: the target must not be a symlink, must be a regular
// file within a bounded size, must not fall under a protected path prefix in
// the policy supplied to this executor (which may differ from the policy in
// effect when the candidate was created), and -- when the candidate carries
// an expected_sha256 captured at detection time -- its current hash must
// still match, so a file that changed after detection is never quarantined
// on stale evidence.
//
// The action ledger is a small pipe-delimited text file appended next to the
// vault ('|' cannot appear in a Windows path, which is this product's
// acceptance platform) so a quarantined file remains restorable after a
// restart; a line that fails to parse is skipped rather than aborting the
// whole load.
class QuarantineExecutor final {
public:
    explicit QuarantineExecutor(std::filesystem::path vault_dir, LocalSecurityPolicy policy = {});

    ErrorCode quarantine(const RemediationCandidate& candidate, QuarantineRecord& out);
    ErrorCode restore(uint64_t record_id);
    ErrorCode shred(uint64_t record_id);
    std::vector<QuarantineRecord> records(size_t count = 100) const;

private:
    static constexpr uintmax_t MAX_QUARANTINE_BYTES = 200ull * 1024 * 1024;
    static constexpr size_t    MAX_LEDGER_RECORDS = 5000;

    std::filesystem::path       vault_dir_;
    std::filesystem::path       ledger_path_;
    LocalSecurityPolicy         policy_;
    mutable std::mutex          mtx_;
    std::deque<QuarantineRecord> ledger_;
    uint64_t                    next_id_{1};

    void load_ledger_locked();
    void append_ledger_locked(const QuarantineRecord& record);
    void rewrite_ledger_locked();
};

} // namespace gcad::security
