#pragma once

#include "observation.hpp"
#include <deque>

namespace gcad::security {

enum class PublishResult : uint8_t {
    ACCEPTED,
    DROPPED_FULL,
    REJECTED_INVALID,
    CLOSED,
};

struct TelemetryMetrics {
    uint64_t accepted{0};
    uint64_t dropped_full{0};
    uint64_t rejected_invalid{0};
    uint64_t rejected_closed{0};
};

class TelemetryBus final {
public:
    explicit TelemetryBus(size_t capacity);

    PublishResult publish(SecurityObservation observation);
    bool try_pop(SecurityObservation& out);
    bool wait_pop(SecurityObservation& out, std::chrono::milliseconds timeout);
    void close();
    TelemetryMetrics metrics() const;
    bool closed() const;

private:
    const size_t                         capacity_;
    mutable std::mutex                   mtx_;
    std::condition_variable              cv_;
    std::deque<SecurityObservation>      queue_;
    bool                                 closed_{false};
    TelemetryMetrics                     metrics_{};
};

} // namespace gcad::security
