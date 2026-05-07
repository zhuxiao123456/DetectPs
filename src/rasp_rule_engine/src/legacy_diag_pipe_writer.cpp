#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "legacy_diag_pipe_writer.h"

#include <cstdint>
#include <limits>

namespace {

LegacyDiagForwardStatus MapCreateFileErrorForDiagPipe(DWORD error)
{
    if (error == ERROR_ACCESS_DENIED) {
        return LegacyDiagForwardStatus::AccessDenied;
    }
    return LegacyDiagForwardStatus::PipeUnavailable;
}

LegacyDiagForwardStatus MapWriteResultForDiagPipe(BOOL ok, DWORD written, DWORD expected)
{
    if (!ok || written != expected) {
        return LegacyDiagForwardStatus::WriteFailed;
    }
    return LegacyDiagForwardStatus::Sent;
}

} // namespace

LegacyDiagForwardStatus LegacyDiagPipeWriter::Send(std::string_view payload)
{
    if (payload.empty()) {
        return LegacyDiagForwardStatus::EmptyPayload;
    }

    if (payload.size() > static_cast<size_t>((std::numeric_limits<uint32_t>::max)())) {
        return LegacyDiagForwardStatus::PayloadTooLarge;
    }

    const DWORD expected = static_cast<DWORD>(payload.size());
    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\rasp_sentry_events",
                               GENERIC_WRITE,
                               0,
                               nullptr,
                               OPEN_EXISTING,
                               0,
                               nullptr);
    if (hPipe == INVALID_HANDLE_VALUE) {
        return MapCreateFileErrorForDiagPipe(GetLastError());
    }

    DWORD written = 0;
    const BOOL ok = WriteFile(hPipe, payload.data(), expected, &written, nullptr);
    const LegacyDiagForwardStatus status = MapWriteResultForDiagPipe(ok, written, expected);
    CloseHandle(hPipe);
    return status;
}
