#pragma once

#include <string>

enum class EventSubmitStatus {
    Submitted,
    DroppedQueueFull,
    DroppedStopping,
    SinkUnavailable,
    InvalidEvent
};

struct DetectionEventLite {
    std::string ruleId;
    std::string sensor;
    std::string decision;
    std::string severity;
    std::string description;
    // Lightweight bounded evidence only. This must not carry a full sample,
    // persisted schema, or the legacy JSONL wire format.
    std::string payload;
};

class IEventSubmitClient {
public:
    virtual ~IEventSubmitClient() = default;
    virtual EventSubmitStatus TrySubmit(const DetectionEventLite& event) = 0;
};
