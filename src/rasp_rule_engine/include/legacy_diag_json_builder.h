#pragma once

#include <cstdint>
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
    std::string message;
    std::string dllInstanceId;
    uint32_t pid = 0;
    std::string processName;
    std::string processPath;
    uint32_t parentPid = 0;
    std::string parentProcessName;
    std::string parentProcessPath;
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
