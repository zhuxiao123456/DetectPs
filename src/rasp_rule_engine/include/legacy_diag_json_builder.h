#pragma once

#include <string>

enum class RaspDiagSeverity {
    Debug,
    Info,
    Warning,
    Error
};

const char* SeverityToString(RaspDiagSeverity severity);

struct LegacyDiagJsonBuildInput {
    std::string id;
    std::string timestamp;
    std::string module;
    std::string pattern;
    std::string message;
    RaspDiagSeverity severity = RaspDiagSeverity::Info;
};

struct LegacyDiagJsonBuildResult {
    std::string compactJson;
    bool truncated = false;
};

class LegacyDiagJsonBuilder {
public:
    LegacyDiagJsonBuildResult Build(const LegacyDiagJsonBuildInput& input) const;
};
