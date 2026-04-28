#include "async_event_queue.h"

#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition)
        std::cerr << "FAIL: " << message << "\n";
    return condition;
}

AsyncEvent MakeEvent(EventPriority priority, const char* id)
{
    AsyncEvent event;
    event.priority = priority;
    event.type = priority == EventPriority::Detection
        ? EventType::Detection
        : EventType::RuntimeTelemetry;
    event.ruleId = id;
    event.decision = priority == EventPriority::Detection ? "block" : "audit";
    event.compactJson = std::string("{\"rule\":\"") + id + "\"}";
    return event;
}

bool HasBalancedJsonObjectShape(const std::string& json)
{
    return json.size() >= 2 && json.front() == '{' && json.back() == '}' &&
           json.find("\"rule\"") != std::string::npos;
}

} // namespace

int main()
{
    {
        AsyncEventQueue queue({4, 1024});
        if (!Expect(queue.TryEnqueue(MakeEvent(EventPriority::Detection, "d1")) == EnqueueResult::Enqueued,
                    "detection enqueue succeeds"))
            return 1;
        AsyncEvent out;
        if (!Expect(queue.TryDequeue(out), "dequeue succeeds"))
            return 1;
        if (!Expect(out.ruleId == "d1", "dequeued event is self-contained copy"))
            return 1;
    }

    {
        AsyncEventQueue queue({1, 1024});
        if (!Expect(queue.TryEnqueue(MakeEvent(EventPriority::DiagLog, "diag")) == EnqueueResult::Enqueued,
                    "diag fills queue"))
            return 1;
        if (!Expect(queue.TryEnqueue(MakeEvent(EventPriority::Detection, "det")) == EnqueueResult::Enqueued,
                    "detection evicts diag when full"))
            return 1;
        AsyncEvent out;
        if (!Expect(queue.TryDequeue(out), "queue has one event"))
            return 1;
        if (!Expect(out.ruleId == "det", "detection is preserved over diag"))
            return 1;
        auto metrics = queue.GetMetrics();
        if (!Expect(metrics.droppedDiagCount == 1, "diag drop is counted"))
            return 1;
    }

    {
        AsyncEventQueue queue({1, 1024});
        queue.TryEnqueue(MakeEvent(EventPriority::Detection, "d1"));
        EnqueueResult r = queue.TryEnqueue(MakeEvent(EventPriority::Detection, "d2"));
        if (!Expect(r == EnqueueResult::DroppedQueueFull, "full detection queue returns queue-full"))
            return 1;
        auto metrics = queue.GetMetrics();
        if (!Expect(metrics.droppedDetectionCount == 1, "dropped detection is counted"))
            return 1;
    }

    {
        AsyncEventQueue queue({4, 256});
        AsyncEvent event = MakeEvent(EventPriority::Detection, "huge");
        event.compactJson = "{\"rule\":\"huge\",\"pattern\":\"" + std::string(1024, 'A') + "\"}";
        EnqueueResult r = queue.TryEnqueue(event);
        if (!Expect(r == EnqueueResult::DroppedTooLarge, "oversized compactJson is dropped instead of truncated"))
            return 1;
        if (!Expect(queue.Size() == 0, "oversized compactJson is not enqueued as broken JSON"))
            return 1;

        AsyncEvent impossible = MakeEvent(EventPriority::Detection, "too-large");
        impossible.ruleId.assign(512, 'R');
        impossible.compactJson.assign(512, 'J');
        r = queue.TryEnqueue(impossible);
        if (!Expect(r == EnqueueResult::DroppedTooLarge, "event too large after truncation is dropped"))
            return 1;
    }

    {
        AsyncEventQueue queue({4, 512});
        AsyncEvent event = MakeEvent(EventPriority::Detection, "valid");
        event.compactJson = "{\"rule\":\"valid\",\"pattern\":\"short\"}";
        EnqueueResult r = queue.TryEnqueue(event);
        if (!Expect(r == EnqueueResult::Enqueued, "valid compactJson within budget is enqueued"))
            return 1;
        AsyncEvent out;
        if (!Expect(queue.TryDequeue(out), "valid compactJson dequeues"))
            return 1;
        if (!Expect(HasBalancedJsonObjectShape(out.compactJson), "queued compactJson remains a complete JSON object"))
            return 1;
    }

    {
        AsyncEventQueue queue({4, 1024});
        queue.Stop();
        if (!Expect(queue.TryEnqueue(MakeEvent(EventPriority::Detection, "after-stop")) == EnqueueResult::DroppedStopping,
                    "stopping queue rejects new events"))
            return 1;
    }

    {
        AsyncEventQueue queue({8, 1024});
        queue.TryEnqueue(MakeEvent(EventPriority::DiagLog, "diag"));
        queue.TryEnqueue(MakeEvent(EventPriority::Telemetry, "tele"));
        queue.TryEnqueue(MakeEvent(EventPriority::Detection, "det"));
        AsyncEvent out;
        queue.TryDequeue(out);
        if (!Expect(out.ruleId == "det", "detection dequeues first"))
            return 1;
        queue.TryDequeue(out);
        if (!Expect(out.ruleId == "tele", "telemetry dequeues second"))
            return 1;
        queue.TryDequeue(out);
        if (!Expect(out.ruleId == "diag", "diag dequeues last"))
            return 1;
    }

    {
        AsyncEventSink sink({32, 1024});
        std::atomic<int> attempts{0};
        std::atomic<int> sent{0};
        sink.Start([&](const AsyncEvent&) {
            attempts.fetch_add(1);
            if (attempts.load() == 1)
                return false;
            sent.fetch_add(1);
            return true;
        });

        sink.TrySubmit(MakeEvent(EventPriority::Detection, "fail-once"));
        sink.TrySubmit(MakeEvent(EventPriority::Detection, "next"));
        std::this_thread::sleep_for(std::chrono::milliseconds(350));
        sink.Stop(std::chrono::milliseconds(1000));

        auto metrics = sink.GetMetrics();
        if (!Expect(metrics.eventsSendFailedTotal >= 1, "send failure is counted"))
            return 1;
        if (!Expect(sent.load() >= 1, "worker continues after failed head event"))
            return 1;
        if (!Expect(metrics.workerBackoffCount >= 1, "worker backoff is counted"))
            return 1;
    }

    {
        AsyncEventSink sink({100000, 1024});
        sink.Start([](const AsyncEvent&) {
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            return true;
        });
        for (int i = 0; i < 200; ++i)
            sink.TrySubmit(MakeEvent(EventPriority::Detection, "flush"));
        auto start = std::chrono::steady_clock::now();
        sink.Stop(std::chrono::milliseconds(25));
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (!Expect(elapsed < std::chrono::milliseconds(500), "flush timeout is bounded"))
            return 1;
        auto metrics = sink.GetMetrics();
        if (!Expect(metrics.shutdownFlushTimeoutCount >= 1, "flush timeout is counted"))
            return 1;
    }

    return 0;
}
