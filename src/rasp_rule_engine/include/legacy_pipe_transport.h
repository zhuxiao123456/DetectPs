#pragma once

#include <cstdint>
#include <string>
#include <string_view>

enum class LegacyPipeStatus {
    Ok,
    Unavailable,
    Timeout,
    AccessDenied,
    IoError
};

struct LegacyPipeRequest {
    std::wstring pipeName;
    std::string payload;
    uint32_t timeoutMs = 100;
};

struct LegacyPipeResponse {
    LegacyPipeStatus status = LegacyPipeStatus::Unavailable;
    std::string payload;
};

class ILegacyPipeTransport {
public:
    virtual ~ILegacyPipeTransport() = default;
    virtual LegacyPipeResponse Transact(const LegacyPipeRequest& request) = 0;
    virtual LegacyPipeStatus Send(std::wstring_view pipeName,
                                  std::string_view payload,
                                  uint32_t timeoutMs) = 0;
};
