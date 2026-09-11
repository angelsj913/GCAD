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

    {
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
    }
    cv_.notify_one();
    return PublishResult::ACCEPTED;
}

bool TelemetryBus::try_pop(SecurityObservation& out) {
    std::lock_guard lk(mtx_);
    if (queue_.empty()) return false;
    out = std::move(queue_.front());
    queue_.pop_front();
    return true;
}

bool TelemetryBus::wait_pop(SecurityObservation& out, std::chrono::milliseconds timeout) {
    std::unique_lock lk(mtx_);
    cv_.wait_for(lk, timeout, [this] { return closed_ || !queue_.empty(); });
    if (queue_.empty()) return false;
    out = std::move(queue_.front());
    queue_.pop_front();
    return true;
}

void TelemetryBus::close() {
    {
        std::lock_guard lk(mtx_);
        closed_ = true;
    }
    cv_.notify_all();
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
