#pragma once

#include <cstdint>
#include <string_view>

enum class EventTransportStatus {
    Sent,
    Timeout,
    AccessDenied,
    Unavailable,
    Failed
};

class IEventTransport {
public:
    virtual ~IEventTransport() = default;
    virtual EventTransportStatus Send(std::string_view payload, uint32_t timeoutMs) = 0;
};
