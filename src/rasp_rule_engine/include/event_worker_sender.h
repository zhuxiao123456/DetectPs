#pragma once

#include "async_event_queue.h"
#include "event_transport.h"

#include <cstdint>

bool SendAsyncEventWorkerOnly(const AsyncEvent& event,
                              IEventTransport& transport,
                              uint32_t timeoutMs);
