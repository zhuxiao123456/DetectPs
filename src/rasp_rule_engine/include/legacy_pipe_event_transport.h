#pragma once

#include "event_transport.h"

#include <string>
#include <string_view>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

class LegacyPipeEventTransport final : public IEventTransport {
public:
    LegacyPipeEventTransport();
    explicit LegacyPipeEventTransport(std::wstring pipeName);

    EventTransportStatus Send(std::string_view payload, uint32_t timeoutMs) override;

private:
    std::wstring pipeName_;
};

EventTransportStatus MapCreateFileErrorForEventPipe(DWORD error);
EventTransportStatus MapWriteFileErrorForEventPipe(DWORD error);
EventTransportStatus MapWriteResultForEventPipe(bool ok, DWORD written, DWORD expected);
