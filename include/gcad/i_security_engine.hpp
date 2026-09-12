#pragma once
#include "common.hpp"
#include "security/observation.hpp"

namespace gcad {

class ISecurityEngine {
public:
    virtual ~ISecurityEngine() = default;
    virtual std::string_view name() const noexcept = 0;
    virtual ErrorCode start() = 0;
    virtual ErrorCode stop() = 0;
    virtual bool running() const noexcept = 0;
    virtual EngineStatus status() const = 0;
    virtual void on_threat(std::function<void(ThreatEvent)> cb) = 0;
    virtual void on_observation(std::function<void(security::SecurityObservation)>) {}
};

} // namespace gcad
