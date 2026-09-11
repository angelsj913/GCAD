#include "gcad/common.hpp"
#include "gcad/engines/self_defense.hpp"
#include "gcad/engines/syscall_guard.hpp"
#include <iostream>

extern void register_test(const char* name, std::function<bool()> fn);

void register_self_defense_tests() {
    register_test("self_defense_name", [] {
        gcad::SelfDefenseEngine engine;
        return engine.name() == "SelfDefense";
    });

    register_test("self_defense_initial_state", [] {
        gcad::SelfDefenseEngine engine;
        if (engine.running()) return false;
        return true;
    });

    register_test("self_defense_status", [] {
        gcad::SelfDefenseEngine engine;
        auto s = engine.status();
        if (s.name != "SelfDefense") return false;
        return true;
    });

#ifdef GCAD_PLATFORM_WINDOWS
    register_test("self_defense_flags_dangerous_process_access", [] {
        return gcad::SelfDefenseEngine::is_dangerous_process_access(PROCESS_VM_WRITE) &&
               gcad::SelfDefenseEngine::is_dangerous_process_access(PROCESS_CREATE_THREAD) &&
               gcad::SelfDefenseEngine::is_dangerous_process_access(PROCESS_TERMINATE);
    });

    register_test("self_defense_allows_benign_query_only_access", [] {
        return !gcad::SelfDefenseEngine::is_dangerous_process_access(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE);
    });

    register_test("self_defense_parse_acl_entries_reads_synthetic_acl", [] {
        std::vector<uint8_t> buf(sizeof(ACL) + sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) + 4, 0);
        auto* header = reinterpret_cast<ACL*>(buf.data());
        header->AclRevision = ACL_REVISION;
        header->AclSize = static_cast<uint16_t>(buf.size());
        header->AceCount = 1;
        auto* ace = reinterpret_cast<ACE_HEADER*>(buf.data() + sizeof(ACL));
        ace->AceType = ACCESS_ALLOWED_ACE_TYPE;
        ace->AceFlags = 0;
        ace->AceSize = static_cast<uint16_t>(sizeof(ACE_HEADER) + sizeof(ACCESS_MASK) + 4);
        const ACCESS_MASK mask = 0x1234;
        std::memcpy(buf.data() + sizeof(ACL) + sizeof(ACE_HEADER), &mask, sizeof(mask));

        const auto entries = gcad::SelfDefenseEngine::parse_acl_entries(buf.data(), buf.size());
        return entries.size() == 1 && entries[0].ace_type == ACCESS_ALLOWED_ACE_TYPE &&
               entries[0].mask == 0x1234u;
    });

    register_test("self_defense_parse_acl_entries_stops_cleanly_on_truncation", [] {
        std::vector<uint8_t> buf(sizeof(ACL) + 1, 0); // header claims an ACE that has no room to exist
        auto* header = reinterpret_cast<ACL*>(buf.data());
        header->AclRevision = ACL_REVISION;
        header->AclSize = static_cast<uint16_t>(buf.size());
        header->AceCount = 1;
        const auto entries = gcad::SelfDefenseEngine::parse_acl_entries(buf.data(), buf.size());
        return entries.empty();
    });

    register_test("self_defense_build_acl_prepends_deny_and_keeps_existing_ace", [] {
        std::vector<uint8_t> existing(sizeof(ACL) + sizeof(ACE_HEADER) + sizeof(ACCESS_MASK), 0);
        auto* header = reinterpret_cast<ACL*>(existing.data());
        header->AclRevision = ACL_REVISION;
        header->AclSize = static_cast<uint16_t>(existing.size());
        header->AceCount = 1;
        auto* ace = reinterpret_cast<ACE_HEADER*>(existing.data() + sizeof(ACL));
        ace->AceType = ACCESS_ALLOWED_ACE_TYPE;
        ace->AceFlags = 0;
        ace->AceSize = static_cast<uint16_t>(sizeof(ACE_HEADER) + sizeof(ACCESS_MASK));
        const ACCESS_MASK existing_mask = 0xAAAA;
        std::memcpy(existing.data() + sizeof(ACL) + sizeof(ACE_HEADER), &existing_mask, sizeof(existing_mask));

        const auto built = gcad::SelfDefenseEngine::build_acl_with_prepended_deny(
            existing.data(), existing.size(), PROCESS_VM_WRITE);
        if (built.empty()) return false;

        const auto entries = gcad::SelfDefenseEngine::parse_acl_entries(built.data(), built.size());
        if (entries.size() != 2) return false;
        if (entries[0].ace_type != ACCESS_DENIED_ACE_TYPE ||
            entries[0].mask != static_cast<uint32_t>(PROCESS_VM_WRITE))
            return false;
        return entries[1].ace_type == ACCESS_ALLOWED_ACE_TYPE && entries[1].mask == 0xAAAAu;
    });

    register_test("self_defense_build_acl_rejects_truncated_existing_acl", [] {
        std::vector<uint8_t> too_small(2, 0);
        return gcad::SelfDefenseEngine::build_acl_with_prepended_deny(
            too_small.data(), too_small.size(), PROCESS_VM_WRITE).empty();
    });
#endif

    register_test("self_defense_start_stop_lifecycle_does_not_crash_or_hang", [] {
        gcad::SelfDefenseEngine engine;
        if (engine.start() != gcad::ErrorCode::OK) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
        if (engine.stop() != gcad::ErrorCode::OK) return false;
        return !engine.running();
    });

#ifdef GCAD_PLATFORM_WINDOWS
    register_test("self_defense_reports_whether_protection_dacl_was_applied", [] {
        gcad::SelfDefenseEngine engine;
        if (engine.start() != gcad::ErrorCode::OK) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const bool applied = engine.protection_applied();
        const bool stopped_cleanly = engine.stop() == gcad::ErrorCode::OK;
        // GetCurrentProcess() is an always-full-access pseudo-handle, so
        // applying our own DACL should not need elevation -- but this test
        // reports the real outcome via stderr rather than assuming it,
        // in case a locked-down environment still refuses WRITE_DAC.
        std::cerr << "  [INFO] SelfDefense::protection_applied() = "
                  << (applied ? "true" : "false") << " in this environment\n";
        return stopped_cleanly;
    });
#endif

    register_test("syscall_guard_name", [] {
        gcad::SyscallGuardEngine engine;
        return engine.name() == "SyscallGuard";
    });

    register_test("syscall_guard_initial_state", [] {
        gcad::SyscallGuardEngine engine;
        if (engine.running()) return false;
        return true;
    });

    register_test("syscall_guard_status", [] {
        gcad::SyscallGuardEngine engine;
        auto s = engine.status();
        if (s.name != "SyscallGuard") return false;
        return true;
    });
}
