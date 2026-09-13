#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <utility>

namespace gcad::ui {

enum class IncidentAction {
    NONE,
    ROLLBACK_FILES,
    RESUME_PROCESS,
    TERMINATE_PROCESS,
};

constexpr bool requires_confirmation(IncidentAction action) noexcept {
    return action != IncidentAction::NONE;
}

struct PendingIncidentAction {
    IncidentAction action{IncidentAction::NONE};
    uint32_t pid{0};
    uint64_t creation_time{0};
    std::string process_name;
};

class IncidentActionGate {
    std::optional<PendingIncidentAction> pending_;

public:
    void request(PendingIncidentAction action) {
        if (requires_confirmation(action.action)) pending_ = std::move(action);
    }

    const PendingIncidentAction* pending() const noexcept {
        return pending_ ? &*pending_ : nullptr;
    }

    void cancel() noexcept { pending_.reset(); }

    template <typename Executor>
    bool confirm(Executor&& execute) {
        if (!pending_) return false;
        auto action = std::move(*pending_);
        pending_.reset();
        std::forward<Executor>(execute)(action);
        return true;
    }
};

} // namespace gcad::ui
