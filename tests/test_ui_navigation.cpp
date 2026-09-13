#include "gcad/ui/navigation.hpp"

#include <functional>

extern void register_test(const char* name, std::function<bool()> fn);

void register_ui_navigation_tests() {
    register_test("ui_primary_navigation_contract", [] {
        using namespace gcad::ui;
        struct ExpectedTarget {
            int tab;
            PrimaryView view;
            IncidentPane incident_pane;
        };
        constexpr ExpectedTarget legacy_targets[] = {
            {0, PrimaryView::OVERVIEW,  IncidentPane::ALERTS},
            {1, PrimaryView::INCIDENTS, IncidentPane::ALERTS},
            {2, PrimaryView::SCAN,      IncidentPane::ALERTS},
            {3, PrimaryView::NETWORK,   IncidentPane::ALERTS},
            {4, PrimaryView::INCIDENTS, IncidentPane::QUARANTINE},
            {5, PrimaryView::FORENSICS, IncidentPane::ALERTS},
            {6, PrimaryView::SETTINGS,  IncidentPane::ALERTS},
        };

        if (primary_view_count() != 6 ||
            primary_view_label(PrimaryView::INCIDENTS) != "Incidents") {
            return false;
        }
        for (const auto& expected : legacy_targets) {
            const auto actual = legacy_tab_target(expected.tab);
            if (actual.view != expected.view || actual.incident_pane != expected.incident_pane) {
                return false;
            }
        }
        const auto below_range = legacy_tab_target(-1);
        const auto above_range = legacy_tab_target(7);
        return below_range.view == PrimaryView::OVERVIEW &&
               below_range.incident_pane == IncidentPane::ALERTS &&
               above_range.view == PrimaryView::OVERVIEW &&
               above_range.incident_pane == IncidentPane::ALERTS;
    });
}
