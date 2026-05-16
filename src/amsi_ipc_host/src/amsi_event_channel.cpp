#include "amsi_event_channel.h"

#include <string>

namespace amsi_ipc {

AmsiEventChannel::AmsiEventChannel(IAmsiEventSink& sink)
    : sink_(sink)
{
}

void AmsiEventChannel::HandleClient(HANDLE pipe)
{
    char buffer[65536] = {};
    DWORD bytesRead = 0;
    const BOOL ok = ReadFile(pipe,
                             buffer,
                             static_cast<DWORD>(sizeof(buffer) - 1),
                             &bytesRead,
                             nullptr);
    if (!ok || bytesRead == 0) {
        return;
    }

    sink_.OnEventLine(AmsiEventLine{std::string(buffer, bytesRead)});
}

} // namespace amsi_ipc
