#pragma once

#include <cstdint>
#include <string>

enum class RuleControlStatus {
    Ok,
    NotReady,
    Disconnected,
    Timeout,
    Faulted
};

// Raw rule bundle used at the control-plane boundary. This is not a compiled
// RuleSnapshot; rule-runtime/scanner-core owns parsing and compilation.
struct RawRuleBundle {
    std::string json;
    std::string libSource;
    uint64_t version = 0;
};

class IRuleControlClient {
public:
    virtual ~IRuleControlClient() = default;
    virtual RuleControlStatus FetchRules(RawRuleBundle& out) = 0;
};
