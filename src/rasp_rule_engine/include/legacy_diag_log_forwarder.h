#pragma once

#include "diag_log_sink.h"

// Legacy diag forwarder seam.
//
// This interface only models compatibility forwarding for diagnostic logs.
// It intentionally does not expose pipe names, HANDLEs, Windows types, JSON
// schema details, event submission clients, event queues, or detection DTOs.
// A future .cpp implementation may use platform APIs behind this boundary.
class ILegacyDiagLogForwarder {
public:
    virtual ~ILegacyDiagLogForwarder() = default;
    virtual bool TryForward(const DiagLogRecord& record) = 0;
};
