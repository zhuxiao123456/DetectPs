#include "amsi_rule_channel.h"

#include <algorithm>
#include <cstdio>
#include <string>

namespace amsi_ipc {

namespace {

constexpr size_t kMaxRuleWireBytes = 2 * 1024 * 1024; // wire bytes, includes trailing '\n'

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

void AmsiRuleChannel::SetLogCallback(AmsiRuleChannelLogCallback callback, void* context)
{
    logCallback_ = callback;
    logContext_ = context;
}

void AmsiRuleChannel::EmitLog(const char* message) const
{
    if (logCallback_ && message) {
        logCallback_(message, logContext_);
    }
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
    if (wire.size() > kMaxRuleWireBytes) {
        char msg[160] = {};
        std::snprintf(msg,
                      sizeof(msg),
                      "rule response too large wireBytes=%zu limit=%zu",
                      wire.size(),
                      kMaxRuleWireBytes);
        EmitLog(msg);
        return;
    }

    DWORD written = 0;
    const DWORD expected = static_cast<DWORD>(wire.size());
    const BOOL ok = WriteFile(pipe, wire.c_str(), expected, &written, nullptr);
    if (!ok || written != expected) {
        return;
    }

    FlushFileBuffers(pipe);
}

} // namespace amsi_ipc
