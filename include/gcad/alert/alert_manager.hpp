#pragma once
#include "../common.hpp"
#include <deque>
#include <mutex>

namespace gcad {

struct AlertRecord {
    uint64_t                              id{0};
    std::chrono::system_clock::time_point timestamp{};
    ThreatLevel                           level{ThreatLevel::SAFE};
    ThreatCategory                        category{ThreatCategory::NONE};
    std::string                           source;
    std::string                           description;
    std::string                           process_name;
    uint32_t                              process_id{0};
    bool                                  acknowledged{false};
};

class AlertManager {
    std::deque<AlertRecord>  history_;
    mutable std::mutex       mtx_;
    std::atomic<uint64_t>    next_id_{1};
    ThreatLevel              min_level_{ThreatLevel::LOW};
    std::atomic<bool>        sound_enabled_{true};
    std::atomic<bool>        toast_enabled_{true};
    static constexpr size_t  MAX_HISTORY = 500;

#ifdef GCAD_PLATFORM_WINDOWS
    struct TrayState;
    std::unique_ptr<TrayState> tray_;
    void init_tray();
    void cleanup_tray();
    void show_balloon(const AlertRecord& rec);
    void play_sound(ThreatLevel level);
#endif

public:
    AlertManager();
    ~AlertManager();

    AlertManager(const AlertManager&) = delete;
    AlertManager& operator=(const AlertManager&) = delete;

    void push(const ThreatEvent& ev);

    std::vector<AlertRecord> recent(size_t n = 50) const;
    size_t total_count() const;
    size_t unacknowledged_count() const;
    void   acknowledge(uint64_t id);
    void   acknowledge_all();
    void   clear();

    void        set_min_level(ThreatLevel level);
    ThreatLevel min_level() const;
    void        set_sound_enabled(bool on);
    bool        sound_enabled() const;
    void        set_toast_enabled(bool on);
    bool        toast_enabled() const;

    static const char* category_source(ThreatCategory cat);
};

} // namespace gcad
