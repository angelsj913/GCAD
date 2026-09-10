#include "gcad/engines/pmsr_engine.hpp"

namespace gcad {

PMSREngine::PMSREngine()
    : rng_(std::random_device{}()) {
    shadow_ring_.reserve(RING_SIZE);
}

PMSREngine::~PMSREngine() { stop(); }

ErrorCode PMSREngine::start() {
    if (running_.load()) return ErrorCode::OK;
    running_.store(true);

    for (size_t i = 0; i < RING_SIZE; ++i) {
        ShadowEntry e{};
        e.original_addr = 0;
        e.xor_key = generate_xor_key();
        e.canary = CANARY_MAGIC ^ e.xor_key;
        e.shadow_hash = compute_shadow_hash(e);
        e.last_check = std::chrono::steady_clock::now();
        shadow_ring_.push_back(e);
    }

#ifdef GCAD_PLATFORM_WINDOWS
    HMODULE hmod = GetModuleHandleA(nullptr);
    if (hmod) {
        auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(hmod);
        if (dos->e_magic == IMAGE_DOS_SIGNATURE) {
            auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uint8_t*>(hmod) + dos->e_lfanew);
            if (nt->Signature == IMAGE_NT_SIGNATURE) {
                uintptr_t code_base = reinterpret_cast<uintptr_t>(hmod) + nt->OptionalHeader.BaseOfCode;
                register_region(code_base, nt->OptionalHeader.SizeOfCode);

                auto& iat_dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT];
                if (iat_dir.VirtualAddress != 0) {
                    uintptr_t iat_base = reinterpret_cast<uintptr_t>(hmod) + iat_dir.VirtualAddress;
                    register_region(iat_base, iat_dir.Size);
                }

                inject_honey_iat(reinterpret_cast<uintptr_t>(hmod) + 0xDEAD0, 0x1337BEEFCAFE0001ull);
                inject_honey_iat(reinterpret_cast<uintptr_t>(hmod) + 0xBEEF0, 0x1337BEEFCAFE0002ull);
            }
        }
    }
#endif

    monitor_thread_ = std::thread(&PMSREngine::monitor_loop, this);
    GCAD_LOG(INFO, "PMSR engine started with shadow ring size " + std::to_string(RING_SIZE));
    return ErrorCode::OK;
}

ErrorCode PMSREngine::stop() {
    if (!running_.load()) return ErrorCode::OK;
    running_.store(false);
    if (monitor_thread_.joinable()) monitor_thread_.join();
    {
        std::lock_guard lk(mtx_);
        for (auto& e : shadow_ring_)
            secure_zero(&e, sizeof(e));
        shadow_ring_.clear();
    }
    return ErrorCode::OK;
}

EngineStatus PMSREngine::status() const {
    EngineStatus s;
    s.name = std::string(name());
    s.running = running_.load();
    s.events_processed = events_processed_.load();
    s.threats_detected = threats_detected_.load();
    s.memory_bytes = shadow_ring_.size() * sizeof(ShadowEntry);
    return s;
}

void PMSREngine::on_threat(std::function<void(ThreatEvent)> cb) {
    std::lock_guard lk(mtx_);
    threat_cb_ = std::move(cb);
}

uint64_t PMSREngine::generate_xor_key() {
    std::uniform_int_distribution<uint64_t> dist;
    return dist(rng_);
}

uint64_t PMSREngine::compute_shadow_hash(const ShadowEntry& entry) const noexcept {
    uint64_t h = 0xcbf29ce484222325ull;
    auto mix = [&](uint64_t v) {
        h ^= v;
        h *= 0x100000001b3ull;
    };
    mix(entry.original_addr);
    mix(entry.xor_key);
    mix(entry.canary);
    return h;
}

bool PMSREngine::verify_canary(const ShadowEntry& entry) const noexcept {
    return (entry.canary ^ entry.xor_key) == CANARY_MAGIC;
}

void PMSREngine::rotate_keys() {
    std::lock_guard lk(mtx_);
    for (auto& entry : shadow_ring_) {
        uint64_t old_decrypted = entry.canary ^ entry.xor_key;
        entry.xor_key = generate_xor_key();
        entry.canary = old_decrypted ^ entry.xor_key;
        entry.shadow_hash = compute_shadow_hash(entry);
        entry.last_check = std::chrono::steady_clock::now();
    }
    events_processed_.fetch_add(1);
}

void PMSREngine::monitor_loop() {
    while (running_.load()) {
        {
            std::lock_guard lk(mtx_);
            for (size_t i = 0; i < shadow_ring_.size(); ++i) {
                auto& entry = shadow_ring_[i];
                if (!verify_canary(entry)) {
                    emit_threat(ThreatCategory::MEMORY_INJECTION,
                        "PMSR canary violation at ring index " + std::to_string(i) +
                        ", addr=0x" + std::format("{:016x}", entry.original_addr));
                    entry.xor_key = generate_xor_key();
                    entry.canary = CANARY_MAGIC ^ entry.xor_key;
                    entry.shadow_hash = compute_shadow_hash(entry);
                }
                if (entry.shadow_hash != compute_shadow_hash(entry)) {
                    emit_threat(ThreatCategory::MEMORY_INJECTION,
                        "PMSR shadow hash mismatch at ring index " + std::to_string(i));
                    entry.shadow_hash = compute_shadow_hash(entry);
                }
                events_processed_.fetch_add(1);
            }
        }

        rotate_keys();
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
}

void PMSREngine::register_region(uintptr_t addr, size_t size) {
    std::lock_guard lk(mtx_);
    size_t idx = addr % RING_SIZE;
    auto& entry = shadow_ring_[idx];
    entry.original_addr = addr;
    entry.xor_key = generate_xor_key();
    entry.canary = CANARY_MAGIC ^ entry.xor_key;
    entry.shadow_hash = compute_shadow_hash(entry);
    entry.last_check = std::chrono::steady_clock::now();
    (void)size;
}

void PMSREngine::inject_honey_iat(uintptr_t fake_addr, uint64_t trap_canary) {
    std::lock_guard lk(mtx_);
    ShadowEntry honey{};
    honey.original_addr = fake_addr;
    honey.xor_key = generate_xor_key();
    honey.canary = trap_canary ^ honey.xor_key;
    honey.shadow_hash = compute_shadow_hash(honey);
    honey.last_check = std::chrono::steady_clock::now();
    if (shadow_ring_.size() < RING_SIZE * 2)
        shadow_ring_.push_back(honey);
}

void PMSREngine::emit_threat(ThreatCategory cat, const std::string& desc, uint32_t pid) {
    threats_detected_.fetch_add(1);
    if (threat_cb_) {
        ThreatEvent ev{};
        ev.level = ThreatLevel::CRITICAL;
        ev.category = cat;
        ev.process_id = pid;
        ev.description = desc;
        threat_cb_(std::move(ev));
    }
}

} // namespace gcad
