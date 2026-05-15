#pragma once

#include <string>

namespace amsi_ipc {

struct AmsiRuleResponse {
    std::string json;
};

class IAmsiRuleProvider {
public:
    virtual ~IAmsiRuleProvider() = default;

    virtual bool BuildRulesResponse(const std::string& command,
                                    AmsiRuleResponse& out,
                                    std::string& error) = 0;

    virtual void InvalidateRuleCache() = 0;
};

} // namespace amsi_ipc
