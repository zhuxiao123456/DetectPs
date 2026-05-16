#pragma once

#include "amsi_control_status_sink.h"
#include "named_pipe_server_pool.h"

namespace amsi_ipc {

class AmsiControlStatusChannel : public INamedPipeClientHandler {
public:
    explicit AmsiControlStatusChannel(IAmsiControlStatusSink& sink);

    void HandleClient(HANDLE pipe) override;

private:
    IAmsiControlStatusSink& sink_;
};

} // namespace amsi_ipc
