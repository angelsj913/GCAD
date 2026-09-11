#include "gcad/security/telemetry_bus.hpp"

namespace gcad::security {

TelemetryBus::TelemetryBus(size_t capacity)
    : capacity_(std::max<size_t>(size_t{1}, capacity)) {}

PublishResult TelemetryBus::publish(SecurityObservation observation) {
    if (!observation.valid()) {
        std::lock_guard lk(mtx_);
        ++metrics_.rejected_invalid;
        return PublishResult::REJECTED_INVALID;
    }

    std::lock_guard lk(mtx_);
    if (closed_) {
        ++metrics_.rejected_closed;
        return PublishResult::CLOSED;
    }
    if (queue_.size() >= capacity_) {
        ++metrics_.dropped_full;
        return PublishResult::DROPPED_FULL;
    }

    queue_.push_back(std::move(observation));
    ++metrics_.accepted;
    return PublishResult::ACCEPTED;
}

bool TelemetryBus::try_pop(SecurityObservation& out) {
    std::lock_guard lk(mtx_);
    if (queue_.empty()) return false;
    out = std::move(queue_.front());
    queue_.pop_front();
    return true;
}

void TelemetryBus::close() {
    std::lock_guard lk(mtx_);
    closed_ = true;
}

TelemetryMetrics TelemetryBus::metrics() const {
    std::lock_guard lk(mtx_);
    return metrics_;
}

bool TelemetryBus::closed() const {
    std::lock_guard lk(mtx_);
    return closed_;
}

} // namespace gcad::security
