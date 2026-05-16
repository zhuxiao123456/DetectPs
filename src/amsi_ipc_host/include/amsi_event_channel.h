#pragma once

#include "amsi_event_sink.h"
#include "named_pipe_server_pool.h"

namespace amsi_ipc {

class AmsiEventChannel : public INamedPipeClientHandler {
public:
    explicit AmsiEventChannel(IAmsiEventSink& sink);

    void HandleClient(HANDLE pipe) override;

private:
    IAmsiEventSink& sink_;
};

} // namespace amsi_ipc
