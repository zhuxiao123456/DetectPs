#pragma once

#include <cstdint>
#include <iosfwd>
#include <map>
#include <string>
#include <vector>

namespace rasp_sentry {

enum class DllInstanceState {
    Online,
    Stale,
    Unloaded,
    Unknown,
};

struct DllInstanceRecord {
    std::string instanceId;
    std::uint32_t pid = 0;
    std::string processStartTime;
    std::string processPath;
    std::uint32_t parentPid = 0;
    std::string parentProcessPath;
    std::int64_t firstSeenMs = 0;
    std::int64_t lastSeenMs = 0;
    DllInstanceState state = DllInstanceState::Unknown;
    bool loadedSeen = false;
    bool ruleLoadSeen = false;
    std::int64_t lastRuleLoadStatusTimeMs = 0;
    std::string lastRuleVersion;
};

struct DllInstanceStats {
    std::size_t onlineDllCount = 0;
    std::size_t staleDllCount = 0;
    std::size_t unloadedDllCount = 0;
    std::size_t historicalLoadedDllCount = 0;
    std::size_t instancesWithRuleLoadResult = 0;
    std::size_t instancesWithoutRuleLoadResult = 0;
};

struct DllInstanceChange {
    bool observed = false;
    bool created = false;
    bool stateChanged = false;
    bool ruleLoadBecameSeen = false;
    std::string instanceId;
    std::uint32_t pid = 0;
    DllInstanceState previousState = DllInstanceState::Unknown;
    DllInstanceState currentState = DllInstanceState::Unknown;
};

class DllInstanceRegistry {
public:
    explicit DllInstanceRegistry(std::int64_t staleThresholdMs = 15 * 60 * 1000,
                                 std::int64_t purgeThresholdMs = 24LL * 60 * 60 * 1000);

    DllInstanceChange ObserveControlStatusPayload(const std::string& payload,
                                                  std::int64_t hostReceiveTimeMs);
    std::vector<DllInstanceChange> RefreshStates(std::int64_t nowMs);
    std::vector<DllInstanceChange> Purge(std::int64_t nowMs);

    DllInstanceStats Stats(std::int64_t nowMs) const;
    void WriteSnapshotJson(std::ostream& output, std::int64_t nowMs) const;

    const DllInstanceRecord* Find(const std::string& instanceId) const;
    std::size_t size() const;
    std::int64_t stale_threshold_ms() const { return staleThresholdMs_; }
    std::int64_t purge_threshold_ms() const { return purgeThresholdMs_; }

private:
    DllInstanceRecord& Upsert(const std::string& instanceId, std::int64_t hostReceiveTimeMs);

    std::map<std::string, DllInstanceRecord> instances_;
    std::size_t historicalLoadedDllCount_ = 0;
    std::int64_t staleThresholdMs_;
    std::int64_t purgeThresholdMs_;
};

const char* DllInstanceStateName(DllInstanceState state);

} // namespace rasp_sentry
