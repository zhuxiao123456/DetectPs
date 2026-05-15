#pragma once

#include "amsi_rule_provider.h"
#include "named_pipe_server_pool.h"

namespace amsi_ipc {

class AmsiRuleChannel : public INamedPipeClientHandler {
public:
    explicit AmsiRuleChannel(IAmsiRuleProvider& provider);

    void HandleClient(HANDLE pipe) override;

private:
    IAmsiRuleProvider& provider_;
};

} // namespace amsi_ipc
