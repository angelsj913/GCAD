#include "gcad/scanner/signature_db.hpp"

namespace gcad {

SignatureDB::SignatureDB() { load_builtin_signatures(); }

void SignatureDB::load_builtin_signatures() {
    // Metasploit/msfvenom shellcode stubs
    add({"msfvenom_x86_shikata", ThreatLevel::CRITICAL, ThreatCategory::SHELLCODE,
         {0xd9, 0x74, 0x24, 0xf4}, {}, -1, "Metasploit shikata_ga_nai encoder stub"});
    add({"msfvenom_x64_shell", ThreatLevel::CRITICAL, ThreatCategory::SHELLCODE,
         {0x48, 0x31, 0xc9, 0x48, 0x81, 0xe9}, {}, -1, "x64 shellcode: xor rcx, sub rcx pattern"});

    // Process injection APIs (PE import patterns)
    add({"inject_VirtualAllocEx", ThreatLevel::HIGH, ThreatCategory::MEMORY_INJECTION,
         {'V','i','r','t','u','a','l','A','l','l','o','c','E','x'}, {}, -1,
         "VirtualAllocEx import — potential process injection"});
    add({"inject_WriteProcessMemory", ThreatLevel::HIGH, ThreatCategory::MEMORY_INJECTION,
         {'W','r','i','t','e','P','r','o','c','e','s','s','M','e','m','o','r','y'}, {}, -1,
         "WriteProcessMemory import — memory injection"});
    add({"inject_NtMapViewOfSection", ThreatLevel::HIGH, ThreatCategory::PROCESS_HOLLOW,
         {'N','t','M','a','p','V','i','e','w','O','f','S','e','c','t','i','o','n'}, {}, -1,
         "NtMapViewOfSection — process hollowing indicator"});
    add({"inject_QueueUserAPC", ThreatLevel::HIGH, ThreatCategory::APC_INJECTION,
         {'Q','u','e','u','e','U','s','e','r','A','P','C'}, {}, -1,
         "QueueUserAPC import — APC injection"});

    // Reflective DLL loader signatures
    add({"reflective_loader", ThreatLevel::CRITICAL, ThreatCategory::REFLECTIVE_LOAD,
         {0x4D, 0x5A, 0x52, 0x45}, {}, 0, "MZ header at non-standard offset (reflective load)"});

    // Mimikatz strings
    add({"mimikatz_str", ThreatLevel::CRITICAL, ThreatCategory::CREDENTIAL_DUMP,
         {'s','e','k','u','r','l','s','a',':',':','l','o','g','o','n','p','a','s','s','w','o','r','d','s'}, {}, -1,
         "Mimikatz credential dump command string"});

    // AMSI bypass pattern
    add({"amsi_patch", ThreatLevel::CRITICAL, ThreatCategory::EVASION_AMSI,
         {'A','m','s','i','S','c','a','n','B','u','f','f','e','r'}, {}, -1,
         "AmsiScanBuffer reference — possible AMSI bypass"});

    // ETW bypass pattern
    add({"etw_patch", ThreatLevel::HIGH, ThreatCategory::EVASION_ETW,
         {'E','t','w','E','v','e','n','t','W','r','i','t','e'}, {}, -1,
         "EtwEventWrite reference — possible ETW bypass"});

    // Direct syscall (Hell's Gate / Halo's Gate)
    add({"syscall_stub_x64", ThreatLevel::CRITICAL, ThreatCategory::DIRECT_SYSCALL,
         {0x4C, 0x8B, 0xD1, 0xB8}, {}, -1,
         "mov r10, rcx; mov eax — direct syscall stub"});

    // Ransomware note strings
    add({"ransom_note_1", ThreatLevel::CRITICAL, ThreatCategory::RANSOMWARE,
         {'Y','o','u','r',' ','f','i','l','e','s',' ','h','a','v','e',' ','b','e','e','n',' ','e','n','c','r','y','p','t','e','d'}, {}, -1,
         "Ransomware note pattern"});

    // ARP spoofing (raw packet)
    add({"arp_reply_spoof", ThreatLevel::HIGH, ThreatCategory::ARP_POISON,
         {0x00, 0x02}, {}, 6, "ARP reply opcode at L2 — potential ARP poisoning"});

    // Cobalt Strike beacon markers
    add({"cs_beacon_cfg", ThreatLevel::CRITICAL, ThreatCategory::FILELESS_EXEC,
         {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBE, 0xEF}, {}, -1,
         "Cobalt Strike beacon configuration marker"});

    // PPID spoofing via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
    add({"ppid_spoof_api", ThreatLevel::HIGH, ThreatCategory::PPID_SPOOF,
         {'U','p','d','a','t','e','P','r','o','c','T','h','r','e','a','d','A','t','t','r','i','b','u','t','e'}, {}, -1,
         "UpdateProcThreadAttribute — possible PPID spoofing"});
}

void SignatureDB::add(Signature sig) {
    std::unique_lock lk(mtx_);
    signatures_.push_back(std::move(sig));
}

void SignatureDB::load_from_file(const std::filesystem::path& path) {
    std::ifstream f(path);
    if (!f) return;
    std::string line;
    while (std::getline(f, line)) {
        if (line.empty() || line[0] == '#') continue;
        // Simple hex pattern format: NAME|LEVEL|HEX_BYTES|DESCRIPTION
        auto sep1 = line.find('|');
        auto sep2 = line.find('|', sep1+1);
        auto sep3 = line.find('|', sep2+1);
        if (sep1 == std::string::npos || sep2 == std::string::npos || sep3 == std::string::npos) continue;

        Signature sig;
        sig.name = line.substr(0, sep1);
        sig.level = static_cast<ThreatLevel>(std::stoi(line.substr(sep1+1, sep2-sep1-1)));
        std::string hex = line.substr(sep2+1, sep3-sep2-1);
        for (size_t i = 0; i + 1 < hex.size(); i += 2) {
            sig.pattern.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
        }
        sig.description = line.substr(sep3+1);
        sig.category = ThreatCategory::SUSPICIOUS_BINARY;
        add(std::move(sig));
    }
}

size_t SignatureDB::size() const {
    std::shared_lock lk(mtx_);
    return signatures_.size();
}

std::optional<SignatureDB::MatchResult> SignatureDB::scan(const uint8_t* data, size_t len) const {
    std::shared_lock lk(mtx_);
    for (auto& sig : signatures_) {
        if (sig.pattern.empty() || sig.pattern.size() > len) continue;
        if (sig.offset >= 0) {
            size_t off = static_cast<size_t>(sig.offset);
            if (off + sig.pattern.size() > len) continue;
            if (std::memcmp(data + off, sig.pattern.data(), sig.pattern.size()) == 0)
                return MatchResult{&sig, off};
        } else {
            for (size_t i = 0; i <= len - sig.pattern.size(); ++i) {
                bool match = true;
                for (size_t j = 0; j < sig.pattern.size(); ++j) {
                    if (!sig.mask.empty() && j < sig.mask.size() && sig.mask[j] == 0) continue;
                    if (data[i + j] != sig.pattern[j]) { match = false; break; }
                }
                if (match) return MatchResult{&sig, i};
            }
        }
    }
    return std::nullopt;
}

std::vector<SignatureDB::MatchResult> SignatureDB::scan_all(const uint8_t* data, size_t len) const {
    std::vector<MatchResult> results;
    std::shared_lock lk(mtx_);
    for (auto& sig : signatures_) {
        if (sig.pattern.empty() || sig.pattern.size() > len) continue;
        size_t start = (sig.offset >= 0) ? static_cast<size_t>(sig.offset) : 0;
        size_t end   = (sig.offset >= 0) ? start + 1 : len - sig.pattern.size() + 1;
        for (size_t i = start; i < end; ++i) {
            if (i + sig.pattern.size() > len) break;
            bool match = true;
            for (size_t j = 0; j < sig.pattern.size(); ++j) {
                if (!sig.mask.empty() && j < sig.mask.size() && sig.mask[j] == 0) continue;
                if (data[i + j] != sig.pattern[j]) { match = false; break; }
            }
            if (match) { results.push_back({&sig, i}); break; }
        }
    }
    return results;
}

} // namespace gcad
