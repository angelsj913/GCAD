#include "gcad/engines/reflective_injection_engine.hpp"
#include <chrono>
#include <cstring>
#include <algorithm>

namespace gcad {

ReflectiveInjectionEngine::ReflectiveInjectionEngine() = default;

ReflectiveInjectionEngine::~ReflectiveInjectionEngine() {
    stop();
}

ErrorCode ReflectiveInjectionEngine::start() {
    if (running_.exchange(true)) return ErrorCode::OK;
    monitor_thread_ = std::thread(&ReflectiveInjectionEngine::monitor_loop, this);
    return ErrorCode::OK;
}

ErrorCode ReflectiveInjectionEngine::stop() {
    if (!running_.exchange(false)) return ErrorCode::OK;
    if (monitor_thread_.joinable()) {
        monitor_thread_.join();
    }
    return ErrorCode::OK;
}

EngineStatus ReflectiveInjectionEngine::status() const {
    EngineStatus st{};
    st.name = std::string(name());
    st.running = running_.load();
    st.events_processed = events_processed_.load();
    st.threats_detected = threats_detected_.load();
    return st;
}

void ReflectiveInjectionEngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard<std::mutex> lock(mtx_);
    threat_cb_ = std::move(cb);
}

void ReflectiveInjectionEngine::emit_threat(const InjectionEvidence& ev) {
    threats_detected_.fetch_add(1, std::memory_order_relaxed);

    std::function<void(ThreatEvent)> cb;
    {
        std::lock_guard<std::mutex> lock(mtx_);
        cb = threat_cb_;
    }

    if (!cb) return;

    ThreatEvent te{};
    te.level = ev.severity;
    te.category = ThreatCategory::MEMORY_INJECTION;
    te.description = ev.detail;
    te.process_id = ev.target_pid;
    te.process_name = ev.process_name;
    te.timestamp = std::chrono::system_clock::now();

    cb(te);
}

bool ReflectiveInjectionEngine::is_rwx_reflective_pe(const uint8_t* memory_bytes, size_t len) {
    if (!memory_bytes || len < 0x100) return false;

    // Check DOS 'MZ'
    if (memory_bytes[0] != 'M' || memory_bytes[1] != 'Z') return false;

    // Read e_lfanew
    uint32_t pe_offset = 0;
    std::memcpy(&pe_offset, memory_bytes + 0x3C, sizeof(uint32_t));
    if (pe_offset + 4 > len) return false;

    // Check PE signature 'PE\0\0'
    if (memory_bytes[pe_offset] == 'P' &&
        memory_bytes[pe_offset + 1] == 'E' &&
        memory_bytes[pe_offset + 2] == '\0' &&
        memory_bytes[pe_offset + 3] == '\0') {
        return true;
    }

    // Check for reflective loader signature strings
    const std::string_view data(reinterpret_cast<const char*>(memory_bytes), len);
    if (data.find("ReflectiveLoader") != std::string_view::npos ||
        data.find("_ReflectiveLoader@") != std::string_view::npos) {
        return true;
    }

    return false;
}

bool ReflectiveInjectionEngine::evaluate_hollowing_anomaly(bool is_suspended, bool unmapped_section, uint32_t entry_point_rva) {
    if (!is_suspended) return false;
    // Suspended process with an unmapped section or zeroed entry point indicates Process Hollowing
    if (unmapped_section || entry_point_rva == 0) {
        return true;
    }
    return false;
}

bool ReflectiveInjectionEngine::evaluate_early_bird_apc(bool thread_created_suspended, bool apc_queued_before_resume, bool is_known_safe) {
    if (is_known_safe) return false;
    // Queuing an APC to a suspended thread before initial resume is the hallmark of Early Bird APC injection
    return thread_created_suspended && apc_queued_before_resume;
}

InjectionEvidence ReflectiveInjectionEngine::inspect_memory_region(
    uint32_t pid, const std::string& proc_name, uintptr_t base_addr,
    const uint8_t* buffer, size_t size, uint32_t protect_flags)
{
    events_processed_.fetch_add(1, std::memory_order_relaxed);

    InjectionEvidence ev{};
    ev.target_pid = pid;
    ev.process_name = proc_name;
    ev.base_address = base_addr;
    ev.region_size = size;

    // 0x40 = PAGE_EXECUTE_READWRITE
    const bool is_rwx = (protect_flags & 0x40) != 0;

    if (buffer && size >= 0x40) {
        if (is_rwx_reflective_pe(buffer, size)) {
            ev.technique = InjectionTechnique::REFLECTIVE_DLL;
            ev.severity = ThreatLevel::CRITICAL;
            ev.detail = "Reflective DLL injection detected: executable PE header located in memory region at 0x" +
                        std::to_string(base_addr) + " [" + proc_name + " PID:" + std::to_string(pid) + "]";
            emit_threat(ev);
            return ev;
        }

        // Check for injected shellcode NOP sled or typical RWX trampolines
        if (is_rwx && size >= 32) {
            size_t nop_count = 0;
            for (size_t i = 0; i < std::min(size, size_t{128}); ++i) {
                if (buffer[i] == 0x90) nop_count++;
            }
            if (nop_count >= 32) {
                ev.technique = InjectionTechnique::THREAD_EXECUTION_HIJACK;
                ev.severity = ThreatLevel::HIGH;
                ev.detail = "Shellcode NOP sled detected in RWX memory block at 0x" +
                            std::to_string(base_addr) + " [" + proc_name + "]";
                emit_threat(ev);
                return ev;
            }
        }
    }

    return ev;
}

void ReflectiveInjectionEngine::monitor_loop() {
    while (running_.load()) {
        for (int i = 0; i < 20 && running_.load(); ++i) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        events_processed_.fetch_add(1, std::memory_order_relaxed);
    }
}

} // namespace gcad
