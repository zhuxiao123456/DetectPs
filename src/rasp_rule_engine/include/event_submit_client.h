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
    std::string payload;
};

class IEventSubmitClient {
public:
    virtual ~IEventSubmitClient() = default;
    virtual EventSubmitStatus TrySubmit(const DetectionEventLite& event) = 0;
};
