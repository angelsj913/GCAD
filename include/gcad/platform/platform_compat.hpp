#pragma once
#include "../common.hpp"

namespace gcad::platform {

struct ProcessInfo {
    uint32_t    pid;
    uint32_t    ppid;
    std::string name;
    std::string path;
    uint64_t    memory_bytes;
    bool        elevated;
};

ErrorCode init();
void      shutdown();

uint32_t  current_pid();
bool      is_elevated();

std::vector<ProcessInfo> enumerate_processes();
bool suspend_process(uint32_t pid);
bool resume_process(uint32_t pid);
bool terminate_process(uint32_t pid);

bool protect_own_process();

std::vector<uint8_t> read_process_memory(uint32_t pid, uintptr_t addr, size_t len);
bool file_exists(const std::filesystem::path& p);
uint64_t file_size(const std::filesystem::path& p);

std::vector<std::filesystem::path> get_system_scan_paths();
std::filesystem::path get_quarantine_dir();

} // namespace gcad::platform
