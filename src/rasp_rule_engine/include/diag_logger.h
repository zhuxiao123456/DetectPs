#pragma once

#include <string_view>

// DiagLogger facade seam.
//
// This header only defines the logger-facing boundary. It must not contain
// sink implementations, platform dependencies, pipe APIs, or detection
// decision semantics.
enum class DiagLogLevel {
    Debug,
    Info,
    Warning,
    Error
};

class IDiagLogger {
public:
    virtual ~IDiagLogger() = default;
    virtual void Log(DiagLogLevel level, std::string_view message) = 0;
};
