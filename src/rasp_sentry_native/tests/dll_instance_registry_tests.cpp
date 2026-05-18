#include "dll_instance_registry.h"

#include <cstdio>
#include <sstream>
#include <string>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        return false;
    }
    return true;
}

} // namespace

int main()
{
    bool ok = true;

    rasp_sentry::DllInstanceRegistry registry(15 * 60 * 1000, 24LL * 60 * 60 * 1000);
    auto change = registry.ObserveControlStatusPayload(
        R"({"msgType":"DLL_LOADED","instanceId":"amsi_detect_1234_20260518T100000000Z_0123456789abcdef","pid":1234,"processStartTime":"2026-05-18T10:00:00.000Z","processPath":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","parentPid":888,"parentProcessPath":"C:\\Windows\\System32\\cmd.exe","timestamp":"2099-01-01T00:00:00Z"})",
        1000);
    ok &= Expect(change.observed && change.created, "DLL_LOADED reports created instance change");
    ok &= Expect(change.currentState == rasp_sentry::DllInstanceState::Online,
                 "DLL_LOADED reports Online state");

    const auto* record = registry.Find("amsi_detect_1234_20260518T100000000Z_0123456789abcdef");
    ok &= Expect(record != nullptr, "DLL_LOADED creates instance record");
    ok &= Expect(record && record->lastSeenMs == 1000, "lastSeen uses HostGuard receive time");
    ok &= Expect(record && record->parentProcessPath.find("cmd.exe") != std::string::npos,
                 "DLL_LOADED stores parent process path");

    change = registry.ObserveControlStatusPayload(
        R"({"msgType":"RULE_LOAD_RESULT","dllInstanceId":"amsi_detect_1234_20260518T100000000Z_0123456789abcdef","pid":1234,"activeVersion":"v1","success":true})",
        2000);
    ok &= Expect(change.ruleLoadBecameSeen, "RULE_LOAD_RESULT reports rule-load transition");
    record = registry.Find("amsi_detect_1234_20260518T100000000Z_0123456789abcdef");
    ok &= Expect(record && record->ruleLoadSeen, "RULE_LOAD_RESULT merges into instance");
    ok &= Expect(record && record->lastRuleVersion == "v1", "RULE_LOAD_RESULT stores rule version");

    auto stats = registry.Stats(1000 + 16 * 60 * 1000);
    ok &= Expect(stats.staleDllCount == 1, "instance becomes stale by host receive time");

    std::ostringstream snapshot;
    registry.WriteSnapshotJson(snapshot, 2000);
    const std::string text = snapshot.str();
    ok &= Expect(text.find("\"onlineDllCount\": 1") != std::string::npos,
                 "snapshot includes online count");
    ok &= Expect(text.find("\"parentProcessPath\":\"C:\\\\Windows\\\\System32\\\\cmd.exe\"") != std::string::npos,
                 "snapshot includes parent process path");
    ok &= Expect(text.find("slot") == std::string::npos &&
                 text.find("admission") == std::string::npos &&
                 text.find("quota") == std::string::npos,
                 "snapshot does not expose slot/admission/quota controls");

    {
        rasp_sentry::DllInstanceRegistry shortRegistry(100, 200);
        shortRegistry.ObserveControlStatusPayload(
            R"({"msgType":"DLL_LOADED","instanceId":"amsi_detect_stale_20260518T100000000Z_aaaaaaaaaaaaaaaa","pid":111})",
            0);
        const auto staleChanges = shortRegistry.RefreshStates(150);
        ok &= Expect(staleChanges.size() == 1 &&
                     staleChanges[0].currentState == rasp_sentry::DllInstanceState::Stale,
                     "RefreshStates reports stale transition");
        change = shortRegistry.ObserveControlStatusPayload(
            R"({"msgType":"DLL_HEARTBEAT","instanceId":"amsi_detect_stale_20260518T100000000Z_aaaaaaaaaaaaaaaa","pid":111})",
            175);
        ok &= Expect(change.stateChanged &&
                     change.previousState == rasp_sentry::DllInstanceState::Stale &&
                     change.currentState == rasp_sentry::DllInstanceState::Online,
                     "heartbeat resumes stale instance");
        change = shortRegistry.ObserveControlStatusPayload(
            R"({"msgType":"DLL_UNLOADED","instanceId":"amsi_detect_stale_20260518T100000000Z_aaaaaaaaaaaaaaaa","pid":111})",
            200);
        ok &= Expect(change.stateChanged &&
                     change.currentState == rasp_sentry::DllInstanceState::Unloaded,
                     "DLL_UNLOADED reports unloaded transition");
        shortRegistry.Purge(450);
        ok &= Expect(shortRegistry.size() == 0,
                     "purge removes unloaded records after purge threshold");

        const auto shortStats = shortRegistry.Stats(250);
        ok &= Expect(shortStats.historicalLoadedDllCount == 1,
                     "purge keeps historical loaded count");
    }

    return ok ? 0 : 1;
}
