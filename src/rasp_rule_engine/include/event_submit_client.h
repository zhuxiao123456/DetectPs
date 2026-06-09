#pragma once

#include <cstdint>
#include <string>
#include <cstddef>

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
    int severity = 2;
    std::string description;
    // Lightweight bounded evidence only. This must not carry a full sample,
    // persisted schema, or the legacy JSONL wire format.
    std::string payload;
};

struct EventJsonBuildInput {
    std::string eventId;
    std::string timestamp;
    std::string moduleName;
    std::string ruleId;
    std::string sensor;
    bool block = false;
    int severity = 2;
    std::string description;
    std::string appName;
    std::string contentName;
    int confidence = 0;
    std::string ip;
    std::string ua;
    std::string payload;
    uint32_t    processPid = 0;
    std::string processName;
    std::string processPath;
    std::string scriptContent;
    // Batch 3: parent process summary.
    uint32_t    parentPid = 0;
    std::string parentProcessName;
    std::string parentProcessPath;
};

struct EventJsonBuildResult {
    std::string compactJson;
    std::string decision;
    std::string payload;
    bool eventTruncated = false;
};

class EventJsonBuilder {
public:
    EventJsonBuildResult BuildDetection(const EventJsonBuildInput& input) const;
};

class IEventSubmitClient {
public:
    virtual ~IEventSubmitClient() = default;
    virtual EventSubmitStatus TrySubmit(const DetectionEventLite& event) = 0;
};
