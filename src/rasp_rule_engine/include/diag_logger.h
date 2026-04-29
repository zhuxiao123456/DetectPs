#pragma once

#include <string_view>

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
