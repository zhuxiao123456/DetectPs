#include "dll_instance_registry.h"

#include <cstdlib>
#include <ostream>

namespace rasp_sentry {
namespace {

std::string JsonEscape(const std::string& value)
{
    std::string out;
    out.reserve(value.size() + 8);
    for (char c : value) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default: out.push_back(c); break;
        }
    }
    return out;
}

std::string ExtractStringField(const std::string& json, const std::string& key)
{
    const std::string needle = "\"" + key + "\"";
    const std::size_t keyPos = json.find(needle);
    if (keyPos == std::string::npos) {
        return {};
    }
    const std::size_t colon = json.find(':', keyPos + needle.size());
    if (colon == std::string::npos) {
        return {};
    }
    std::size_t value = colon + 1;
    while (value < json.size() && (json[value] == ' ' || json[value] == '\t')) {
        ++value;
    }
    if (value >= json.size()) {
        return {};
    }
    if (json[value] != '"') {
        std::size_t end = value;
        while (end < json.size() && json[end] != ',' && json[end] != '}') {
            ++end;
        }
        return json.substr(value, end - value);
    }
    ++value;
    std::string out;
    while (value < json.size()) {
        const char c = json[value++];
        if (c == '"') {
            break;
        }
        if (c == '\\' && value < json.size()) {
            const char escaped = json[value++];
            switch (escaped) {
            case '"': out.push_back('"'); break;
            case '\\': out.push_back('\\'); break;
            case 'n': out.push_back('\n'); break;
            case 'r': out.push_back('\r'); break;
            case 't': out.push_back('\t'); break;
            default: out.push_back(escaped); break;
            }
        } else {
            out.push_back(c);
        }
    }
    return out;
}

std::uint32_t ParseUint32(const std::string& value)
{
    if (value.empty()) {
        return 0;
    }
    char* end = nullptr;
    const unsigned long parsed = std::strtoul(value.c_str(), &end, 10);
    if (end == value.c_str()) {
        return 0;
    }
    return static_cast<std::uint32_t>(parsed);
}

std::string FallbackInstanceId(std::uint32_t pid)
{
    return std::string("amsi_detect_") + std::to_string(pid) + "_unknown";
}

} // namespace

DllInstanceRegistry::DllInstanceRegistry(std::int64_t staleThresholdMs,
                                         std::int64_t purgeThresholdMs)
    : staleThresholdMs_(staleThresholdMs),
      purgeThresholdMs_(purgeThresholdMs)
{
}

DllInstanceRecord& DllInstanceRegistry::Upsert(const std::string& instanceId,
                                               std::int64_t hostReceiveTimeMs)
{
    DllInstanceRecord& record = instances_[instanceId];
    if (record.instanceId.empty()) {
        record.instanceId = instanceId;
        record.firstSeenMs = hostReceiveTimeMs;
        ++historicalLoadedDllCount_;
    }
    record.lastSeenMs = hostReceiveTimeMs;
    if (record.state != DllInstanceState::Unloaded) {
        record.state = DllInstanceState::Online;
    }
    return record;
}

DllInstanceChange DllInstanceRegistry::ObserveControlStatusPayload(const std::string& payload,
                                                                   std::int64_t hostReceiveTimeMs)
{
    const std::string msgType = ExtractStringField(payload, "msgType");
    if (msgType.empty()) {
        return {};
    }

    std::string instanceId = ExtractStringField(payload, "instanceId");
    if (instanceId.empty()) {
        instanceId = ExtractStringField(payload, "dllInstanceId");
    }
    const std::uint32_t pid = ParseUint32(ExtractStringField(payload, "pid"));
    if (instanceId.empty()) {
        instanceId = FallbackInstanceId(pid);
    }

    const auto beforeIt = instances_.find(instanceId);
    const bool existed = beforeIt != instances_.end();
    const DllInstanceState previousState = existed ? beforeIt->second.state : DllInstanceState::Unknown;
    const bool previousRuleLoadSeen = existed && beforeIt->second.ruleLoadSeen;

    auto makeChange = [&](const DllInstanceRecord& record) {
        DllInstanceChange change;
        change.observed = true;
        change.created = !existed;
        change.instanceId = record.instanceId;
        change.pid = record.pid;
        change.previousState = previousState;
        change.currentState = record.state;
        change.stateChanged = previousState != record.state;
        change.ruleLoadBecameSeen = !previousRuleLoadSeen && record.ruleLoadSeen;
        return change;
    };

    if (msgType == "DLL_LOADED") {
        DllInstanceRecord& record = Upsert(instanceId, hostReceiveTimeMs);
        record.loadedSeen = true;
        record.pid = pid;
        record.processStartTime = ExtractStringField(payload, "processStartTime");
        record.processPath = ExtractStringField(payload, "processPath");
        record.parentPid = ParseUint32(ExtractStringField(payload, "parentPid"));
        record.parentProcessPath = ExtractStringField(payload, "parentProcessPath");
        record.state = DllInstanceState::Online;
        return makeChange(record);
    }

    if (msgType == "DLL_HEARTBEAT") {
        DllInstanceRecord& record = Upsert(instanceId, hostReceiveTimeMs);
        if (record.pid == 0) {
            record.pid = pid;
        }
        record.state = DllInstanceState::Online;
        return makeChange(record);
    }

    if (msgType == "DLL_UNLOADED") {
        DllInstanceRecord& record = Upsert(instanceId, hostReceiveTimeMs);
        if (record.pid == 0) {
            record.pid = pid;
        }
        record.state = DllInstanceState::Unloaded;
        return makeChange(record);
    }

    if (msgType == "RULE_LOAD_RESULT") {
        DllInstanceRecord& record = Upsert(instanceId, hostReceiveTimeMs);
        if (record.pid == 0) {
            record.pid = pid;
        }
        record.ruleLoadSeen = true;
        record.lastRuleLoadStatusTimeMs = hostReceiveTimeMs;
        record.lastRuleVersion = ExtractStringField(payload, "activeVersion");
        if (record.state != DllInstanceState::Unloaded) {
            record.state = DllInstanceState::Online;
        }
        return makeChange(record);
    }

    return {};
}

std::vector<DllInstanceChange> DllInstanceRegistry::RefreshStates(std::int64_t nowMs)
{
    std::vector<DllInstanceChange> changes;
    for (auto& entry : instances_) {
        DllInstanceRecord& record = entry.second;
        if (record.state == DllInstanceState::Online &&
            nowMs - record.lastSeenMs > staleThresholdMs_) {
            DllInstanceChange change;
            change.observed = true;
            change.instanceId = record.instanceId;
            change.pid = record.pid;
            change.previousState = record.state;
            record.state = DllInstanceState::Stale;
            change.currentState = record.state;
            change.stateChanged = true;
            changes.push_back(std::move(change));
        }
    }
    return changes;
}

std::vector<DllInstanceChange> DllInstanceRegistry::Purge(std::int64_t nowMs)
{
    std::vector<DllInstanceChange> changes;
    for (auto it = instances_.begin(); it != instances_.end();) {
        const DllInstanceRecord& record = it->second;
        const bool purgeable = record.state == DllInstanceState::Stale ||
                               record.state == DllInstanceState::Unloaded;
        if (purgeable && nowMs - record.lastSeenMs > purgeThresholdMs_) {
            DllInstanceChange change;
            change.observed = true;
            change.instanceId = record.instanceId;
            change.pid = record.pid;
            change.previousState = record.state;
            change.currentState = record.state;
            changes.push_back(std::move(change));
            it = instances_.erase(it);
        } else {
            ++it;
        }
    }
    return changes;
}

DllInstanceStats DllInstanceRegistry::Stats(std::int64_t nowMs) const
{
    DllInstanceStats stats;
    stats.historicalLoadedDllCount = historicalLoadedDllCount_;
    for (const auto& entry : instances_) {
        DllInstanceRecord record = entry.second;
        if (record.state == DllInstanceState::Online &&
            nowMs - record.lastSeenMs > staleThresholdMs_) {
            record.state = DllInstanceState::Stale;
        }
        switch (record.state) {
        case DllInstanceState::Online: ++stats.onlineDllCount; break;
        case DllInstanceState::Stale: ++stats.staleDllCount; break;
        case DllInstanceState::Unloaded: ++stats.unloadedDllCount; break;
        case DllInstanceState::Unknown: break;
        }
        if (record.ruleLoadSeen) {
            ++stats.instancesWithRuleLoadResult;
        } else if (record.state == DllInstanceState::Online ||
                   record.state == DllInstanceState::Stale) {
            ++stats.instancesWithoutRuleLoadResult;
        }
    }
    return stats;
}

void DllInstanceRegistry::WriteSnapshotJson(std::ostream& output, std::int64_t nowMs) const
{
    const DllInstanceStats stats = Stats(nowMs);
    output << "{\n"
           << "  \"onlineDllCount\": " << stats.onlineDllCount << ",\n"
           << "  \"staleDllCount\": " << stats.staleDllCount << ",\n"
           << "  \"unloadedDllCount\": " << stats.unloadedDllCount << ",\n"
           << "  \"historicalLoadedDllCount\": " << stats.historicalLoadedDllCount << ",\n"
           << "  \"instancesWithRuleLoadResult\": " << stats.instancesWithRuleLoadResult << ",\n"
           << "  \"instancesWithoutRuleLoadResult\": " << stats.instancesWithoutRuleLoadResult << ",\n"
           << "  \"heartbeatIntervalMs\": " << 5 * 60 * 1000 << ",\n"
           << "  \"staleThresholdMs\": " << staleThresholdMs_ << ",\n"
           << "  \"instances\": [\n";

    bool first = true;
    for (const auto& entry : instances_) {
        DllInstanceRecord record = entry.second;
        if (record.state == DllInstanceState::Online &&
            nowMs - record.lastSeenMs > staleThresholdMs_) {
            record.state = DllInstanceState::Stale;
        }
        if (!first) {
            output << ",\n";
        }
        first = false;
        output << "    {"
               << "\"instanceId\":\"" << JsonEscape(record.instanceId) << "\","
               << "\"state\":\"" << DllInstanceStateName(record.state) << "\","
               << "\"pid\":" << record.pid << ","
               << "\"processStartTime\":\"" << JsonEscape(record.processStartTime) << "\","
               << "\"processPath\":\"" << JsonEscape(record.processPath) << "\","
               << "\"parentPid\":" << record.parentPid << ","
               << "\"parentProcessPath\":\"" << JsonEscape(record.parentProcessPath) << "\","
               << "\"firstSeenMs\":" << record.firstSeenMs << ","
               << "\"lastSeenMs\":" << record.lastSeenMs << ","
               << "\"ruleLoadSeen\":" << (record.ruleLoadSeen ? "true" : "false") << ","
               << "\"lastRuleVersion\":\"" << JsonEscape(record.lastRuleVersion) << "\""
               << "}";
    }

    output << "\n  ]\n"
           << "}\n";
}

const DllInstanceRecord* DllInstanceRegistry::Find(const std::string& instanceId) const
{
    const auto it = instances_.find(instanceId);
    return it == instances_.end() ? nullptr : &it->second;
}

std::size_t DllInstanceRegistry::size() const
{
    return instances_.size();
}

const char* DllInstanceStateName(DllInstanceState state)
{
    switch (state) {
    case DllInstanceState::Online: return "Online";
    case DllInstanceState::Stale: return "Stale";
    case DllInstanceState::Unloaded: return "Unloaded";
    case DllInstanceState::Unknown: return "Unknown";
    }
    return "Unknown";
}

} // namespace rasp_sentry
