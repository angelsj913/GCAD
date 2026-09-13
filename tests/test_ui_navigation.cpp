#include "gcad/ui/navigation.hpp"

#include <functional>

extern void register_test(const char* name, std::function<bool()> fn);

void register_ui_navigation_tests() {
    register_test("ui_primary_navigation_contract", [] {
        using namespace gcad::ui;
        return primary_view_count() == 6 &&
               primary_view_label(PrimaryView::INCIDENTS) == "Incidents" &&
               legacy_tab_target(1).incident_pane == IncidentPane::ALERTS &&
               legacy_tab_target(4).view == PrimaryView::INCIDENTS &&
               legacy_tab_target(4).incident_pane == IncidentPane::QUARANTINE;
    });
}
