#include "../include/legacy_pipe_event_transport.h"

#include <limits>
#include <utility>

namespace {

bool WriteFileWithTimeout(HANDLE pipe, std::string_view payload, uint32_t timeoutMs, DWORD& written)
{
    written = 0;
    const DWORD expected = static_cast<DWORD>(payload.size());
    const DWORD boundedTimeoutMs = timeoutMs == 0 ? 1000 : timeoutMs;

    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent)
        return false;

    BOOL ok = WriteFile(pipe, payload.data(), expected, nullptr, &ov);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok && error == ERROR_IO_PENDING) {
        DWORD wait = WaitForSingleObject(ov.hEvent, boundedTimeoutMs);
        if (wait == WAIT_OBJECT_0) {
            ok = GetOverlappedResult(pipe, &ov, &written, TRUE);
        } else {
            CancelIo(pipe);
            GetOverlappedResult(pipe, &ov, &written, TRUE);
            SetLastError(ERROR_TIMEOUT);
            ok = FALSE;
        }
    } else if (ok) {
        ok = GetOverlappedResult(pipe, &ov, &written, TRUE);
    }

    CloseHandle(ov.hEvent);
    return ok == TRUE;
}

} // namespace

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
    if (payload.size() > static_cast<size_t>((std::numeric_limits<DWORD>::max)()))
        return EventTransportStatus::Failed;

    HANDLE pipe = CreateFileW(pipeName_.c_str(),
                              GENERIC_WRITE,
                              0,
                              nullptr,
                              OPEN_EXISTING,
                              FILE_FLAG_OVERLAPPED,
                              nullptr);
    if (pipe == INVALID_HANDLE_VALUE)
        return MapCreateFileErrorForEventPipe(GetLastError());

    DWORD written = 0;
    const DWORD expected = static_cast<DWORD>(payload.size());
    BOOL ok = WriteFileWithTimeout(pipe, payload, timeoutMs, written) ? TRUE : FALSE;
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
