#pragma once

#include "amsi_rule_provider.h"
#include "named_pipe_server_pool.h"

namespace amsi_ipc {

using AmsiRuleChannelLogCallback = void (*)(const char* message, void* context);

class AmsiRuleChannel : public INamedPipeClientHandler {
public:
    explicit AmsiRuleChannel(IAmsiRuleProvider& provider);

    void SetLogCallback(AmsiRuleChannelLogCallback callback, void* context);
    void HandleClient(HANDLE pipe) override;

private:
    void EmitLog(const char* message) const;

    IAmsiRuleProvider& provider_;
    AmsiRuleChannelLogCallback logCallback_ = nullptr;
    void* logContext_ = nullptr;
};

} // namespace amsi_ipc
