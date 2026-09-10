#pragma once
#include "../../scanner/deep_scanner.hpp"

namespace gcad::ui::views {

class ScanView {
    int  selected_mode_{0};
    char custom_path_[512]{};
    bool scan_requested_{false};
    float scan_anim_{0.0f};

public:
    void render(DeepScanner& scanner);

private:
    void render_mode_selector(DeepScanner& scanner);
    void render_progress(const ScanProgress& prog);
    void render_results(const std::vector<ScanResult>& results);
    void render_radar_effect(float progress);
};

} // namespace gcad::ui::views
