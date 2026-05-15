#include "amsi_rule_channel.h"

#include <algorithm>
#include <string>

namespace amsi_ipc {

namespace {

void TrimCommand(std::string& command)
{
    while (!command.empty() &&
           (command.back() == '\n' || command.back() == '\r' || command.back() == ' ')) {
        command.pop_back();
    }
}

} // namespace

AmsiRuleChannel::AmsiRuleChannel(IAmsiRuleProvider& provider)
    : provider_(provider)
{
}

void AmsiRuleChannel::HandleClient(HANDLE pipe)
{
    char requestBuffer[64] = {};
    DWORD bytesRead = 0;
    if (!ReadFile(pipe,
                  requestBuffer,
                  static_cast<DWORD>(sizeof(requestBuffer) - 1),
                  &bytesRead,
                  nullptr)) {
        return;
    }

    requestBuffer[bytesRead] = '\0';
    std::string command(requestBuffer, bytesRead);
    TrimCommand(command);

    AmsiRuleResponse response;
    std::string error;
    if (!provider_.BuildRulesResponse(command, response, error) || response.json.empty()) {
        return;
    }

    std::string wire = response.json + "\n";
    DWORD written = 0;
    WriteFile(pipe, wire.c_str(), static_cast<DWORD>(wire.size()), &written, nullptr);
    FlushFileBuffers(pipe);
}

} // namespace amsi_ipc
