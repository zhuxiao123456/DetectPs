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

struct RuleSnapshotPayload {
    std::string json;
    std::string libSource;
    uint64_t version = 0;
};

class IRuleControlClient {
public:
    virtual ~IRuleControlClient() = default;
    virtual RuleControlStatus FetchRules(RuleSnapshotPayload& out) = 0;
};
