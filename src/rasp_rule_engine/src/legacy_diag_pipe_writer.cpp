#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "legacy_diag_pipe_writer.h"

#include <cstdint>
#include <limits>

namespace {

constexpr DWORD kDiagPipeWriteTimeoutMs = 500;

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

bool WriteFileWithTimeout(HANDLE pipe, std::string_view payload, DWORD timeoutMs, DWORD& written)
{
    written = 0;
    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) {
        return false;
    }

    const DWORD expected = static_cast<DWORD>(payload.size());
    BOOL ok = WriteFile(pipe, payload.data(), expected, nullptr, &ov);
    DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    if (!ok && error == ERROR_IO_PENDING) {
        DWORD wait = WaitForSingleObject(ov.hEvent, timeoutMs);
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

LegacyDiagForwardStatus LegacyDiagPipeWriter::Send(std::string_view payload)
{
    if (payload.empty()) {
        return LegacyDiagForwardStatus::EmptyPayload;
    }

    if (payload.size() > static_cast<size_t>((std::numeric_limits<uint32_t>::max)())) {
        return LegacyDiagForwardStatus::PayloadTooLarge;
    }

    const DWORD expected = static_cast<DWORD>(payload.size());
    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\amsi_detect_logs",
                               GENERIC_WRITE,
                               0,
                               nullptr,
                               OPEN_EXISTING,
                               FILE_FLAG_OVERLAPPED,
                               nullptr);
    if (hPipe == INVALID_HANDLE_VALUE) {
        return MapCreateFileErrorForDiagPipe(GetLastError());
    }

    DWORD written = 0;
    const BOOL ok = WriteFileWithTimeout(hPipe, payload, kDiagPipeWriteTimeoutMs, written) ? TRUE : FALSE;
    const LegacyDiagForwardStatus status = MapWriteResultForDiagPipe(ok, written, expected);
    CloseHandle(hPipe);
    return status;
}
