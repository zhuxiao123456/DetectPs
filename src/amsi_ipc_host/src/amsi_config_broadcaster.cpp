#include "amsi_config_broadcaster.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <utility>

namespace amsi_ipc {

AmsiConfigBroadcaster::AmsiConfigBroadcaster(std::wstring configPipeName)
    : configPipeName_(std::move(configPipeName))
{
}

AmsiBroadcastResult AmsiConfigBroadcaster::Broadcast(AmsiControlSignal signal,
                                                     int maxListeners,
                                                     std::uint32_t timeoutMs) const
{
    AmsiBroadcastResult result{};
    const auto rawSignal = static_cast<std::uint8_t>(signal);

    for (int i = 0; i < maxListeners; ++i) {
        if (!WaitNamedPipeW(configPipeName_.c_str(), timeoutMs)) {
            result.lastError = GetLastError();
            break;
        }

        HANDLE pipe = CreateFileW(configPipeName_.c_str(),
                                  GENERIC_WRITE,
                                  0,
                                  nullptr,
                                  OPEN_EXISTING,
                                  0,
                                  nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            result.lastError = GetLastError();
            break;
        }

        DWORD written = 0;
        const BOOL ok = WriteFile(pipe, &rawSignal, 1, &written, nullptr);
        const DWORD writeError = ok ? ERROR_SUCCESS : GetLastError();
        CloseHandle(pipe);

        if (!ok || written != 1) {
            result.lastError = writeError;
            break;
        }

        ++result.reached;
        result.lastError = ERROR_SUCCESS;
    }

    return result;
}

} // namespace amsi_ipc
