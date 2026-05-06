#pragma once

#include "diag_logger.h"

#include <string>

// Diag log output sink seam.
//
// A sink is an output target such as OutputDebugString, a ring buffer, or a
// future product log adapter. It receives only lightweight diagnostic records
// and must not understand detection events, rules, or platform result values.
struct DiagLogRecord {
    DiagLogLevel level = DiagLogLevel::Info;
    std::string module;
    std::string message;
};

class IDiagLogSink {
public:
    virtual ~IDiagLogSink() = default;
    virtual bool TrySubmit(const DiagLogRecord& record) = 0;
};
