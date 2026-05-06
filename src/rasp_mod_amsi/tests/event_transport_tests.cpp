#include "async_event_queue.h"
#include "event_transport.h"
#include "event_worker_sender.h"

#include <iostream>
#include <string>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition)
        std::cerr << "FAIL: " << message << "\n";
    return condition;
}

class FakeEventTransport final : public IEventTransport {
public:
    explicit FakeEventTransport(EventTransportStatus status)
        : status_(status)
    {
    }

    EventTransportStatus Send(std::string_view payload, uint32_t timeoutMs) override
    {
        ++calls;
        lastPayload.assign(payload.data(), payload.size());
        lastTimeoutMs = timeoutMs;
        return status_;
    }

    int calls = 0;
    std::string lastPayload;
    uint32_t lastTimeoutMs = 0;

private:
    EventTransportStatus status_;
};

AsyncEvent MakeEvent()
{
    AsyncEvent event;
    event.priority = EventPriority::Detection;
    event.type = EventType::Detection;
    event.pid = 11;
    event.tid = 22;
    event.ruleId = "rule-1";
    event.decision = "block";
    event.contentName = "demo.ps1";
    event.appName = "powershell.exe";
    event.sampleHash = "hash";
    event.sampleLen = 123;
    event.reason = "reason";
    event.compactJson = "{\"id\":\"fixed\"}";
    event.eventTruncated = true;
    return event;
}

bool EventsEqual(const AsyncEvent& left, const AsyncEvent& right)
{
    return left.priority == right.priority &&
           left.type == right.type &&
           left.timestamp == right.timestamp &&
           left.pid == right.pid &&
           left.tid == right.tid &&
           left.ruleId == right.ruleId &&
           left.decision == right.decision &&
           left.contentName == right.contentName &&
           left.appName == right.appName &&
           left.sampleHash == right.sampleHash &&
           left.sampleLen == right.sampleLen &&
           left.reason == right.reason &&
           left.compactJson == right.compactJson &&
           left.eventTruncated == right.eventTruncated;
}

} // namespace

int main()
{
    {
        AsyncEvent event = MakeEvent();
        AsyncEvent before = event;
        FakeEventTransport transport(EventTransportStatus::Sent);
        bool ok = SendAsyncEventWorkerOnly(event, transport, 250);

        if (!Expect(ok, "Sent maps to true"))
            return 1;
        if (!Expect(transport.calls == 1, "non-empty compactJson calls transport"))
            return 1;
        if (!Expect(transport.lastPayload == event.compactJson, "transport receives compactJson bytes"))
            return 1;
        if (!Expect(transport.lastTimeoutMs == 250, "timeout is forwarded"))
            return 1;
        if (!Expect(EventsEqual(event, before), "wrapper does not modify AsyncEvent"))
            return 1;
    }

    {
        const EventTransportStatus failures[] = {
            EventTransportStatus::Failed,
            EventTransportStatus::Timeout,
            EventTransportStatus::AccessDenied,
            EventTransportStatus::Unavailable,
        };
        for (EventTransportStatus status : failures) {
            AsyncEvent event = MakeEvent();
            AsyncEvent before = event;
            FakeEventTransport transport(status);
            bool ok = SendAsyncEventWorkerOnly(event, transport, 100);

            if (!Expect(!ok, "non-Sent transport status maps to false"))
                return 1;
            if (!Expect(transport.calls == 1, "failure status still calls transport once"))
                return 1;
            if (!Expect(EventsEqual(event, before), "failure path does not modify AsyncEvent"))
                return 1;
        }
    }

    {
        AsyncEvent event = MakeEvent();
        event.compactJson.clear();
        AsyncEvent before = event;
        FakeEventTransport transport(EventTransportStatus::Sent);
        bool ok = SendAsyncEventWorkerOnly(event, transport, 100);

        if (!Expect(!ok, "empty compactJson maps to false"))
            return 1;
        if (!Expect(transport.calls == 0, "empty compactJson does not call transport"))
            return 1;
        if (!Expect(EventsEqual(event, before), "empty payload path does not modify AsyncEvent"))
            return 1;
    }

    return 0;
}
