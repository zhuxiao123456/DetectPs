#pragma once

struct ProcessContextSnapshot;

struct ScanContext {
    const ProcessContextSnapshot* process = nullptr;
    bool emitProcessPathFields = false;
};
