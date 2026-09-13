#pragma once

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

} // namespace gcad::ui
