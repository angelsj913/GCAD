#pragma once

#include <cstddef>
#include <string_view>

namespace gcad::ui {

enum class PrimaryView {
    OVERVIEW,
    SCAN,
    NETWORK,
    INCIDENTS,
    FORENSICS,
    SETTINGS,
};

enum class IncidentPane {
    ALERTS,
    QUARANTINE,
};

struct NavigationTarget {
    PrimaryView view;
    IncidentPane incident_pane;
};

constexpr std::size_t primary_view_count() noexcept {
    return 6;
}

constexpr std::string_view primary_view_label(PrimaryView view) noexcept {
    switch (view) {
        case PrimaryView::OVERVIEW:   return "Overview";
        case PrimaryView::SCAN:       return "Scan";
        case PrimaryView::NETWORK:    return "Network";
        case PrimaryView::INCIDENTS:  return "Incidents";
        case PrimaryView::FORENSICS:  return "Forensics";
        case PrimaryView::SETTINGS:   return "Settings";
    }
    return "Overview";
}

constexpr NavigationTarget legacy_tab_target(int tab) noexcept {
    switch (tab) {
        case 1: return {PrimaryView::INCIDENTS, IncidentPane::ALERTS};
        case 2: return {PrimaryView::SCAN, IncidentPane::ALERTS};
        case 3: return {PrimaryView::NETWORK, IncidentPane::ALERTS};
        case 4: return {PrimaryView::INCIDENTS, IncidentPane::QUARANTINE};
        case 5: return {PrimaryView::FORENSICS, IncidentPane::ALERTS};
        case 6: return {PrimaryView::SETTINGS, IncidentPane::ALERTS};
        default: return {PrimaryView::OVERVIEW, IncidentPane::ALERTS};
    }
}

} // namespace gcad::ui
