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
