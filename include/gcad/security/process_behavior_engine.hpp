#pragma once

#include "observation.hpp"

namespace gcad::security {

class ProcessBehaviorEngine final {
public:
    std::vector<SecurityObservation> inspect_pid(uint32_t pid) const;
};

} // namespace gcad::security
