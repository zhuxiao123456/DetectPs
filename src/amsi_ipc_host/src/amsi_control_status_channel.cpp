#include "amsi_control_status_channel.h"

#include <string>

namespace amsi_ipc {

AmsiControlStatusChannel::AmsiControlStatusChannel(IAmsiControlStatusSink& sink)
    : sink_(sink)
{
}

void AmsiControlStatusChannel::HandleClient(HANDLE pipe)
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

    sink_.OnControlStatusLine(AmsiControlStatusLine{std::string(buffer, bytesRead)});
}

} // namespace amsi_ipc
