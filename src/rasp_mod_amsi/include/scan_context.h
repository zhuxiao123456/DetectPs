#pragma once

#include <memory>

struct ProcessContextSnapshot;

struct ScanContext {
    std::shared_ptr<const ProcessContextSnapshot> processSnapshot;
    const ProcessContextSnapshot* process = nullptr;
    bool emitProcessPathFields = false;
};
