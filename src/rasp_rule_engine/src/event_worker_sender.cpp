#include "../include/event_worker_sender.h"

bool SendAsyncEventWorkerOnly(const AsyncEvent& event,
                              IEventTransport& transport,
                              uint32_t timeoutMs)
{
    if (event.compactJson.empty())
        return false;

    return transport.Send(event.compactJson, timeoutMs) == EventTransportStatus::Sent;
}