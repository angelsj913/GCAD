#include "gcad/security/process_behavior_engine.hpp"

#ifdef GCAD_PLATFORM_WINDOWS
#include <tlhelp32.h>
#endif

namespace gcad::security {

#ifdef GCAD_PLATFORM_WINDOWS
namespace {

std::string process_image(HANDLE process) {
    std::array<char, MAX_PATH> image{};
    DWORD size = static_cast<DWORD>(image.size());
    if (!QueryFullProcessImageNameA(process, 0, image.data(), &size)) return {};
    return std::string(image.data(), size);
}

uint64_t creation_time(uint32_t pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return 0;
    FILETIME created{}, exited{}, kernel{}, user{};
    uint64_t result = 0;
    if (GetProcessTimes(process, &created, &exited, &kernel, &user)) {
        result = (static_cast<uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    }
    CloseHandle(process);
    return result;
}

std::optional<uint32_t> parent_pid(uint32_t pid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return std::nullopt;
    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(entry);
    std::optional<uint32_t> parent;
    if (Process32First(snapshot, &entry)) {
        do {
            if (entry.th32ProcessID == pid) {
                parent = entry.th32ParentProcessID;
                break;
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return parent;
}

SecurityObservation make_observation(ObservationKind kind, ThreatLevel level, double confidence,
                                     uint32_t pid, const std::string& image, std::string evidence) {
    SecurityObservation observation{};
    observation.source_id = "process-behavior";
    observation.kind = kind;
    observation.timestamp = std::chrono::system_clock::now();
    observation.suggested_level = level;
    observation.confidence = confidence;
    observation.process_id = pid;
    observation.process_name = image;
    observation.file_path = image;
    observation.evidence = std::move(evidence);
    return observation;
}

} // namespace
#endif

std::vector<SecurityObservation> ProcessBehaviorEngine::inspect_pid(uint32_t pid) const {
#ifndef GCAD_PLATFORM_WINDOWS
    (void)pid;
    return {};
#else
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!process) return {};

    const std::string image = process_image(process);
    std::vector<SecurityObservation> observations;
    constexpr size_t max_regions = 4096;
    uintptr_t address = 0;
    for (size_t inspected = 0; inspected < max_regions; ++inspected) {
        MEMORY_BASIC_INFORMATION memory{};
        if (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(address), &memory, sizeof(memory)) != sizeof(memory))
            break;
        const uintptr_t base = reinterpret_cast<uintptr_t>(memory.BaseAddress);
        const uintptr_t next = base + memory.RegionSize;
        if (next <= address) break;
        address = next;

        const DWORD writable_executable = PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        if (memory.State == MEM_COMMIT && (memory.Protect & writable_executable) != 0 &&
            (memory.Protect & (PAGE_GUARD | PAGE_NOACCESS)) == 0) {
            observations.push_back(make_observation(
                ObservationKind::PROCESS_MEMORY, ThreatLevel::HIGH, 0.65, pid, image,
                "Committed executable-writable memory region observed at 0x" + std::format("{:x}", base)));
            break;
        }
    }
    CloseHandle(process);

    const auto parent = parent_pid(pid);
    if (parent && *parent != 0 && *parent != pid) {
        const uint64_t child_created = creation_time(pid);
        const uint64_t parent_created = creation_time(*parent);
        if (child_created != 0 && parent_created != 0 && parent_created > child_created) {
            observations.push_back(make_observation(
                ObservationKind::PROCESS_LINEAGE, ThreatLevel::HIGH, 0.90, pid, image,
                "Claimed live parent PID " + std::to_string(*parent) + " was created after this process"));
        }
    }
    return observations;
#endif
}

} // namespace gcad::security
