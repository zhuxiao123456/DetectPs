#include "../include/async_event_queue.h"

#include <algorithm>

namespace {

uint64_t NowMs()
{
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
}

} // namespace

AsyncEventQueue::AsyncEventQueue(AsyncEventQueueOptions options)
    : options_(options)
{
}

EnqueueResult AsyncEventQueue::TryEnqueue(const AsyncEvent& event)
{
    if (stopping_.load()) {
        enqueueStoppingDropCount_.fetch_add(1);
        RecordDrop(event.priority);
        return EnqueueResult::DroppedStopping;
    }

    AsyncEvent copy = event;
    if (!PrepareEvent(copy)) {
        enqueueTooLargeDropCount_.fetch_add(1);
        RecordDrop(event.priority);
        return EnqueueResult::DroppedTooLarge;
    }

    std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
    if (!lock.owns_lock()) {
        enqueueLockContentionCount_.fetch_add(1);
        RecordDrop(copy.priority);
        return EnqueueResult::DroppedLockContention;
    }

    if (stopping_.load()) {
        enqueueStoppingDropCount_.fetch_add(1);
        RecordDrop(copy.priority);
        return EnqueueResult::DroppedStopping;
    }

    if (!HasCapacityLocked() && !MakeRoomLocked(copy.priority)) {
        RecordDrop(copy.priority);
        return EnqueueResult::DroppedQueueFull;
    }

    switch (copy.priority) {
    case EventPriority::Detection:
        high_.push_back(std::move(copy));
        break;
    case EventPriority::Telemetry:
        medium_.push_back(std::move(copy));
        break;
    case EventPriority::DiagLog:
        low_.push_back(std::move(copy));
        break;
    }

    eventsEnqueuedTotal_.fetch_add(1);
    if (event.eventTruncated)
        eventsTruncatedTotal_.fetch_add(1);
    UpdateSizeMetricsLocked();
    lock.unlock();
    cv_.notify_one();
    return EnqueueResult::Enqueued;
}

bool AsyncEventQueue::TryDequeue(AsyncEvent& event)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!high_.empty()) {
        event = std::move(high_.front());
        high_.pop_front();
    } else if (!medium_.empty()) {
        event = std::move(medium_.front());
        medium_.pop_front();
    } else if (!low_.empty()) {
        event = std::move(low_.front());
        low_.pop_front();
    } else {
        return false;
    }
    return true;
}

bool AsyncEventQueue::WaitDequeue(AsyncEvent& event, std::chrono::milliseconds timeout)
{
    std::unique_lock<std::mutex> lock(mutex_);
    cv_.wait_for(lock, timeout, [&]() {
        return stopping_.load() || CurrentSizeLocked() > 0;
    });

    if (!high_.empty()) {
        event = std::move(high_.front());
        high_.pop_front();
        return true;
    }
    if (!medium_.empty()) {
        event = std::move(medium_.front());
        medium_.pop_front();
        return true;
    }
    if (!low_.empty()) {
        event = std::move(low_.front());
        low_.pop_front();
        return true;
    }
    return false;
}

void AsyncEventQueue::Stop()
{
    stopping_.store(true);
    cv_.notify_all();
}

size_t AsyncEventQueue::DropRemaining()
{
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = CurrentSizeLocked();
    for (const auto& event : high_)
        RecordDrop(event.priority);
    for (const auto& event : medium_)
        RecordDrop(event.priority);
    for (const auto& event : low_)
        RecordDrop(event.priority);
    high_.clear();
    medium_.clear();
    low_.clear();
    return count;
}

AsyncEventMetrics AsyncEventQueue::GetMetrics() const
{
    AsyncEventMetrics m;
    m.eventsEnqueuedTotal = eventsEnqueuedTotal_.load();
    m.eventsSentTotal = eventsSentTotal_.load();
    m.eventsSendFailedTotal = eventsSendFailedTotal_.load();
    m.eventsDroppedTotal = eventsDroppedTotal_.load();
    m.droppedDetectionCount = droppedDetectionCount_.load();
    m.droppedTelemetryCount = droppedTelemetryCount_.load();
    m.droppedDiagCount = droppedDiagCount_.load();
    m.queueCurrentSize = static_cast<uint64_t>(Size());
    m.queueHighWatermark = queueHighWatermark_.load();
    m.sentryDisconnectedCount = sentryDisconnectedCount_.load();
    m.workerBackoffCount = workerBackoffCount_.load();
    m.shutdownFlushTimeoutCount = shutdownFlushTimeoutCount_.load();
    m.eventsTruncatedTotal = eventsTruncatedTotal_.load();
    m.enqueueLockContentionCount = enqueueLockContentionCount_.load();
    m.enqueueStoppingDropCount = enqueueStoppingDropCount_.load();
    m.enqueueTooLargeDropCount = enqueueTooLargeDropCount_.load();
    return m;
}

size_t AsyncEventQueue::Size() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return CurrentSizeLocked();
}

void AsyncEventQueue::RecordSendSuccess()
{
    eventsSentTotal_.fetch_add(1);
}

void AsyncEventQueue::RecordSendFailure()
{
    eventsSendFailedTotal_.fetch_add(1);
    sentryDisconnectedCount_.fetch_add(1);
}

void AsyncEventQueue::RecordBackoff()
{
    workerBackoffCount_.fetch_add(1);
}

void AsyncEventQueue::RecordShutdownFlushTimeout()
{
    shutdownFlushTimeoutCount_.fetch_add(1);
}

bool AsyncEventQueue::PrepareEvent(AsyncEvent& event)
{
    if (event.timestamp == 0)
        event.timestamp = NowMs();
    if (event.pid == 0)
        event.pid = GetCurrentProcessId();
    if (event.tid == 0)
        event.tid = GetCurrentThreadId();

    size_t size = EstimateEventBytes(event);
    if (size <= options_.maxEventBytes)
        return true;

    return false;
}

size_t AsyncEventQueue::EstimateEventBytes(const AsyncEvent& event) const
{
    return event.ruleId.size() +
           event.decision.size() +
           event.contentName.size() +
           event.appName.size() +
           event.sampleHash.size() +
           event.reason.size() +
           event.compactJson.size() +
           128;
}

size_t AsyncEventQueue::CurrentSizeLocked() const
{
    return high_.size() + medium_.size() + low_.size();
}

bool AsyncEventQueue::HasCapacityLocked() const
{
    return CurrentSizeLocked() < options_.maxEvents;
}

bool AsyncEventQueue::MakeRoomLocked(EventPriority priority)
{
    if (options_.maxEvents == 0)
        return false;

    if (priority == EventPriority::Detection) {
        if (!low_.empty()) {
            DropOneLocked(EventPriority::DiagLog);
            return true;
        }
        if (!medium_.empty()) {
            DropOneLocked(EventPriority::Telemetry);
            return true;
        }
        return false;
    }

    if (priority == EventPriority::Telemetry) {
        if (!low_.empty()) {
            DropOneLocked(EventPriority::DiagLog);
            return true;
        }
        return false;
    }

    return false;
}

void AsyncEventQueue::DropOneLocked(EventPriority priority)
{
    switch (priority) {
    case EventPriority::Detection:
        if (!high_.empty())
            high_.pop_front();
        break;
    case EventPriority::Telemetry:
        if (!medium_.empty())
            medium_.pop_front();
        break;
    case EventPriority::DiagLog:
        if (!low_.empty())
            low_.pop_front();
        break;
    }
    RecordDrop(priority);
}

void AsyncEventQueue::RecordDrop(EventPriority priority)
{
    eventsDroppedTotal_.fetch_add(1);
    switch (priority) {
    case EventPriority::Detection:
        droppedDetectionCount_.fetch_add(1);
        break;
    case EventPriority::Telemetry:
        droppedTelemetryCount_.fetch_add(1);
        break;
    case EventPriority::DiagLog:
        droppedDiagCount_.fetch_add(1);
        break;
    }
}

void AsyncEventQueue::UpdateSizeMetricsLocked()
{
    uint64_t size = static_cast<uint64_t>(CurrentSizeLocked());
    uint64_t current = queueHighWatermark_.load();
    while (size > current &&
           !queueHighWatermark_.compare_exchange_weak(current, size)) {
    }
}

AsyncEventSink::AsyncEventSink(AsyncEventQueueOptions options)
    : queue_(options)
{
}

AsyncEventSink::~AsyncEventSink()
{
    Stop(std::chrono::milliseconds(100));
}

bool AsyncEventSink::Start(Sender sender)
{
    if (running_.exchange(true))
        return true;
    sender_ = std::move(sender);
    try {
        worker_ = std::thread(&AsyncEventSink::WorkerLoop, this);
        return true;
    } catch (...) {
        running_.store(false);
        queue_.Stop();
        return false;
    }
}

EnqueueResult AsyncEventSink::TrySubmit(const AsyncEvent& event)
{
    if (!running_.load())
        return EnqueueResult::DroppedStopping;
    return queue_.TryEnqueue(event);
}

void AsyncEventSink::Stop(std::chrono::milliseconds flushTimeout)
{
    if (!running_.exchange(false))
        return;

    queue_.Stop();
    stopCv_.notify_all();
    auto deadline = std::chrono::steady_clock::now() + flushTimeout;
    {
        std::unique_lock<std::mutex> lock(stopMutex_);
        while (queue_.Size() > 0 && std::chrono::steady_clock::now() < deadline) {
            stopCv_.wait_until(lock, deadline);
        }
    }

    if (queue_.Size() > 0) {
        queue_.RecordShutdownFlushTimeout();
        queue_.DropRemaining();
        stopCv_.notify_all();
    }

    if (worker_.joinable())
        worker_.join();
}

AsyncEventMetrics AsyncEventSink::GetMetrics() const
{
    return queue_.GetMetrics();
}

void AsyncEventSink::WorkerLoop()
{
    while (running_.load() || queue_.Size() > 0) {
        AsyncEvent event;
        if (!queue_.WaitDequeue(event, std::chrono::milliseconds(100)))
            continue;

        bool ok = sender_ ? sender_(event) : false;
        if (ok) {
            queue_.RecordSendSuccess();
            ResetBackoff();
            stopCv_.notify_all();
        } else {
            queue_.RecordSendFailure();
            queue_.RecordBackoff();
            stopCv_.notify_all();
            auto backoff = NextBackoff();
            std::unique_lock<std::mutex> lock(stopMutex_);
            stopCv_.wait_for(lock, backoff, [&]() {
                return !running_.load();
            });
        }
    }
}

std::chrono::milliseconds AsyncEventSink::NextBackoff()
{
    static const int steps[] = {100, 200, 500, 1000, 2000, 5000};
    size_t idx = (std::min)(static_cast<size_t>(consecutiveFailures_),
                            (sizeof(steps) / sizeof(steps[0])) - 1);
    ++consecutiveFailures_;
    return std::chrono::milliseconds(steps[idx]);
}

void AsyncEventSink::ResetBackoff()
{
    consecutiveFailures_ = 0;
}
