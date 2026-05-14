#include "legacy_pipe_event_transport.h"

#include <limits>
#include <utility>

LegacyPipeEventTransport::LegacyPipeEventTransport()
    : LegacyPipeEventTransport(LR"(\\.\pipe\amsi_detect_events)")
{
}

LegacyPipeEventTransport::LegacyPipeEventTransport(std::wstring pipeName)
    : pipeName_(std::move(pipeName))
{
}

EventTransportStatus LegacyPipeEventTransport::Send(std::string_view payload, uint32_t timeoutMs)
{
    (void)timeoutMs;

    if (payload.size() > static_cast<size_t>((std::numeric_limits<DWORD>::max)()))
        return EventTransportStatus::Failed;

    HANDLE pipe = CreateFileW(pipeName_.c_str(),
                              GENERIC_WRITE,
                              0,
                              nullptr,
                              OPEN_EXISTING,
                              0,
                              nullptr);
    if (pipe == INVALID_HANDLE_VALUE)
        return MapCreateFileErrorForEventPipe(GetLastError());

    DWORD written = 0;
    const DWORD expected = static_cast<DWORD>(payload.size());
    BOOL ok = WriteFile(pipe,
                        payload.data(),
                        expected,
                        &written,
                        nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(pipe);

    if (!ok)
        return MapWriteFileErrorForEventPipe(error);

    return MapWriteResultForEventPipe(true, written, expected);
}

EventTransportStatus MapCreateFileErrorForEventPipe(DWORD error)
{
    switch (error) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PIPE_BUSY:
        return EventTransportStatus::Unavailable;
    case ERROR_ACCESS_DENIED:
        return EventTransportStatus::AccessDenied;
    default:
        return EventTransportStatus::Failed;
    }
}

EventTransportStatus MapWriteFileErrorForEventPipe(DWORD error)
{
    if (error == ERROR_ACCESS_DENIED)
        return EventTransportStatus::AccessDenied;
    return EventTransportStatus::Failed;
}

EventTransportStatus MapWriteResultForEventPipe(bool ok, DWORD written, DWORD expected)
{
    if (!ok)
        return EventTransportStatus::Failed;
    if (written != expected)
        return EventTransportStatus::Failed;
    return EventTransportStatus::Sent;
}
