#pragma once

#include <string>

struct LegacyDiagJsonBuildInput {
    std::string id;
    std::string timestamp;
    std::string module;
    std::string pattern;
    std::string message;
};

struct LegacyDiagJsonBuildResult {
    std::string compactJson;
    bool truncated = false;
};

class LegacyDiagJsonBuilder {
public:
    LegacyDiagJsonBuildResult Build(const LegacyDiagJsonBuildInput& input) const;
};

