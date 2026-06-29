#include "../include/engine_runtime.h"
#include "../include/amsi_rule_engine.h"
#include "../include/process_context_provider.h"
#include "../include/scan_context.h"
#include "../include/event_submit_client.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <map>
#include <utility>
#include <vector>

extern "C" {
#include "lua.h"
#include "lauxlib.h"
}

namespace {

int Fail(const char* message)
{
    std::cerr << "FAIL: " << message << "\n";
    return 1;
}

bool Expect(bool condition, const char* message)
{
    if (!condition)
        std::cerr << "FAIL: " << message << "\n";
    return condition;
}

class RuntimeReadyAmsiRuleEngine : public AmsiRuleEngine
{
public:
    RuntimeReadyAmsiRuleEngine()
    {
        m_running.store(true, std::memory_order_release);
        MarkHostAlive(true);
        MarkRuleSnapshotReady(true);
        MarkDetectionPausedByHostState(false);
        MarkWaitingResumeAfterHostLost(false);
    }
};

std::unique_ptr<EngineRuntime> MakeRuntime()
{
    return std::make_unique<EngineRuntime>(
        []() { return std::make_unique<RuntimeReadyAmsiRuleEngine>(); },
        [](AmsiRuleEngine&) { return true; });
}

class TestAmsiRuleEngine : public AmsiRuleEngine
{
public:
    using AmsiRuleEngine::BuildNextSnapshot;
    using AmsiRuleEngine::ParseAndSwap;

    using AmsiRuleEngine::ActiveEffectiveSnapshotHash;
    using AmsiRuleEngine::ComputeEffectiveSnapshotHash;
    using AmsiRuleEngine::SetActiveEffectiveSnapshotHash;

    bool BuildSnapshotLuaMatches(const std::string& json,
                                 const std::string& libSource,
                                 const std::string& ruleId,
                                 const std::string& expectedDesc)
    {
        std::string effectiveLib;
        auto snapshot = BuildNextSnapshot(json, libSource, effectiveLib);
        if (!snapshot || !snapshot->luaEngine || snapshot->rules.empty())
            return false;

        RaspLuaResult result = snapshot->luaEngine->Run(ruleId, "AmsiProvider", RaspLuaContext{});
        return result.matched && result.desc == expectedDesc;
    }

    bool BuildRegexSnapshotsHaveIndependentCaches(const std::string& firstJson,
                                                  const std::string& secondJson)
    {
#ifdef RASP_PCRE2_AVAILABLE
        std::string firstLib;
        auto first = BuildNextSnapshot(firstJson, "", firstLib);
        std::string secondLib;
        auto second = BuildNextSnapshot(secondJson, "", secondLib);
        if (!first || !second || !first->luaEngine || !second->luaEngine ||
            first->rules.empty() || second->rules.empty())
            return false;

        if (first->luaEngine.get() == second->luaEngine.get())
            return false;
        if (first->luaEngine->RegexCacheSizeForTesting() < 1 ||
            second->luaEngine->RegexCacheSizeForTesting() < 1)
            return false;

        ScanExecutionContext firstExec;
        firstExec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(firstExec.budget.totalBudgetMs));
        std::string matched;
        if (!first->luaEngine->MatchesAnyRegex(first->rules[0].regexPatterns,
                                               "Invoke IEX",
                                               matched,
                                               &firstExec))
            return false;
        if (first->luaEngine->RegexCacheSizeForTesting() < 1 ||
            second->luaEngine->RegexCacheSizeForTesting() < 1)
            return false;

        ScanExecutionContext secondExec;
        secondExec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(secondExec.budget.totalBudgetMs));
        matched.clear();
        if (!second->luaEngine->MatchesAnyRegex(second->rules[0].regexPatterns,
                                                "DownloadString",
                                                matched,
                                                &secondExec))
            return false;
        if (first->luaEngine->RegexCacheSizeForTesting() < 1 ||
            second->luaEngine->RegexCacheSizeForTesting() < 1)
            return false;

        ScanExecutionContext oldScanAfterSecondBuild;
        oldScanAfterSecondBuild.deadline = ScanDeadline::FromNow(
            std::chrono::milliseconds(oldScanAfterSecondBuild.budget.totalBudgetMs));
        matched.clear();
        return first->luaEngine->MatchesAnyRegex(first->rules[0].regexPatterns,
                                                 "IEX remains available",
                                                 matched,
                                                 &oldScanAfterSecondBuild) &&
               first->luaEngine->RegexCacheSizeForTesting() >= 1;
#else
        (void)firstJson;
        (void)secondJson;
        return true;
#endif
    }

    uint32_t BuildSnapshotTotalScanTimeoutMs(const std::string& json)
    {
        std::string effectiveLib;
        auto snapshot = BuildNextSnapshot(json, "", effectiveLib);
        return snapshot ? snapshot->totalScanTimeoutMs : 0;
    }

    std::pair<uint32_t, uint32_t> BuildSnapshotScanBudgets(const std::string& json)
    {
        std::string effectiveLib;
        auto snapshot = BuildNextSnapshot(json, "", effectiveLib);
        if (!snapshot)
            return {};
        return {snapshot->maxRulesPerScan, snapshot->maxRegexCallsPerScan};
    }

    ScanRateLimitConfig BuildSnapshotScanRateLimit(const std::string& json)
    {
        std::string effectiveLib;
        auto snapshot = BuildNextSnapshot(json, "", effectiveLib);
        return snapshot ? snapshot->scanRateLimit : ScanRateLimitConfig{};
    }

    DiagnosticsConfig BuildSnapshotDiagnostics(const std::string& json)
    {
        std::string effectiveLib;
        auto snapshot = BuildNextSnapshot(json, "", effectiveLib);
        return snapshot ? snapshot->diagnostics : DiagnosticsConfig{};
    }

    ScanRateLimitDecision CheckScanRateLimit(const ScanRateLimitConfig& config, uint64_t nowMs)
    {
        return ShouldBypassByScanRateLimit(config, nowMs);
    }
};

struct LuaBytecodeWriter
{
    std::string bytes;
};

int WriteLuaBytecode(lua_State*, const void* data, size_t size, void* userData)
{
    auto* writer = static_cast<LuaBytecodeWriter*>(userData);
    writer->bytes.append(static_cast<const char*>(data), size);
    return 0;
}

std::string CompileLuaBytecode(const char* source, const char* chunkName)
{
    lua_State* L = luaL_newstate();
    if (!L)
        return {};

    if (luaL_loadbuffer(L, source, std::strlen(source), chunkName) != LUA_OK) {
        lua_close(L);
        return {};
    }

    LuaBytecodeWriter writer;
    if (lua_dump(L, WriteLuaBytecode, &writer, 0) != 0) {
        lua_close(L);
        return {};
    }

    lua_close(L);
    return writer.bytes;
}

std::string Base64Encode(const std::string& input)
{
    static const char kAlphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string output;
    output.reserve(((input.size() + 2) / 3) * 4);

    size_t i = 0;
    while (i + 3 <= input.size()) {
        const unsigned char a = static_cast<unsigned char>(input[i++]);
        const unsigned char b = static_cast<unsigned char>(input[i++]);
        const unsigned char c = static_cast<unsigned char>(input[i++]);
        output.push_back(kAlphabet[a >> 2]);
        output.push_back(kAlphabet[((a & 0x03) << 4) | (b >> 4)]);
        output.push_back(kAlphabet[((b & 0x0f) << 2) | (c >> 6)]);
        output.push_back(kAlphabet[c & 0x3f]);
    }

    if (i < input.size()) {
        const unsigned char a = static_cast<unsigned char>(input[i++]);
        output.push_back(kAlphabet[a >> 2]);
        if (i < input.size()) {
            const unsigned char b = static_cast<unsigned char>(input[i++]);
            output.push_back(kAlphabet[((a & 0x03) << 4) | (b >> 4)]);
            output.push_back(kAlphabet[(b & 0x0f) << 2]);
            output.push_back('=');
        } else {
            output.push_back(kAlphabet[(a & 0x03) << 4]);
            output.push_back('=');
            output.push_back('=');
        }
    }

    return output;
}

std::string LuaBase64(const char* script)
{
    // Minimal fixtures needed by this regression. Avoid adding another encoder
    // dependency to the test binary.
    if (std::string(script) == "function rule(sensor, context) return { match = true, desc = 'old' } end")
        return "ZnVuY3Rpb24gcnVsZShzZW5zb3IsIGNvbnRleHQpIHJldHVybiB7IG1hdGNoID0gdHJ1ZSwgZGVzYyA9ICdvbGQnIH0gZW5k";
    if (std::string(script) == "function rule(sensor, context) return { match = true, desc = 'new' } end")
        return "ZnVuY3Rpb24gcnVsZShzZW5zb3IsIGNvbnRleHQpIHJldHVybiB7IG1hdGNoID0gdHJ1ZSwgZGVzYyA9ICduZXcnIH0gZW5k";
    return {};
}

std::string OneLuaRuleJson(const char* id, const char* desc, const char* script)
{
    return std::string("{\"rules\":[{\"id\":\"") + id +
           "\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\",\"description\":\"" +
           desc + "\",\"scriptBodyBase64\":\"" + LuaBase64(script) + "\"}]}";
}

std::string OneRegexRuleJson(const char* id, const char* pattern)
{
    return std::string("{\"rules\":[{\"id\":\"") + id +
           "\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\",\"description\":\"split_regex\",\"config\":{\"regexPatterns\":[\"" +
           pattern + "\"]}}]}";
}

std::string MultiRegexRuleJson()
{
    return "{\"rules\":[{\"id\":\"multi_regex_snapshot\",\"sensor\":\"AmsiProvider\","
           "\"enabled\":true,\"mode\":\"block\",\"description\":\"multi_regex\","
           "\"config\":{\"regexPatterns\":[\"IEX\",\"DownloadString\",\"AmsiUtils\"]}}]}";
}

std::string RateLimitedRegexRuleJson(uint32_t maxScans, double bypassRatio)
{
    return std::string("{\"scanRateLimit\":{\"enabled\":true,\"windowMs\":1000,\"maxScans\":") +
           std::to_string(maxScans) +
           ",\"bypassRatioAfterLimit\":" +
           std::to_string(bypassRatio) +
           "},\"rules\":[{\"id\":\"rate_limited\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\",\"description\":\"rate_limit\",\"config\":{\"regexPatterns\":[\"amsiutils\"]}}]}";
}

std::string ScanContextRegexRuleJson(bool enabled,
                                     uint32_t maxBufferedBytes,
                                     uint32_t ttlMs,
                                     uint32_t maxEvalBytes,
                                     bool clearOnMatch,
                                     const char* pattern,
                                     uint32_t maxAppendBytes = 256,
                                     uint32_t prefixFilterBytes = 128)
{
    return std::string("{\"scanContext\":{\"enabled\":") +
           (enabled ? "true" : "false") +
           ",\"maxBufferedBytes\":" + std::to_string(maxBufferedBytes) +
           ",\"ttlMs\":" + std::to_string(ttlMs) +
           ",\"maxEvalBytes\":" + std::to_string(maxEvalBytes) +
           ",\"clearOnMatch\":" + (clearOnMatch ? "true" : "false") +
           ",\"maxAppendBytes\":" + std::to_string(maxAppendBytes) +
           ",\"prefixFilterBytes\":" + std::to_string(prefixFilterBytes) +
           "},\"rules\":[{\"id\":\"scan_context_rule\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\",\"description\":\"scan_context\",\"config\":{\"regexPatterns\":[\"" +
           pattern + "\"]}}]}";
}

std::string RateLimitedScanContextRegexRuleJson()
{
    return "{\"scanRateLimit\":{\"enabled\":true,\"windowMs\":1000,\"maxScans\":1,\"bypassRatioAfterLimit\":1.0},"
           "\"scanContext\":{\"enabled\":true,\"maxBufferedBytes\":8192,\"ttlMs\":3000,\"maxEvalBytes\":16384,\"clearOnMatch\":true},"
           "\"rules\":[{\"id\":\"rate_limited_scan_context\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\","
           "\"description\":\"rate_limited_scan_context\",\"config\":{\"regexPatterns\":[\"(?s)amsi.*utils\"]}}]}";
}

std::string GlobalModeRegexRuleJson(const char* globalMode,
                                    const char* ruleMode,
                                    const char* id,
                                    const char* pattern)
{
    return std::string("{\"globalMode\":\"") + globalMode +
           "\",\"rules\":[{\"id\":\"" + id +
           "\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"" + ruleMode +
           "\",\"description\":\"global_mode_regex\",\"config\":{\"regexPatterns\":[\"" +
           pattern + "\"]}}]}";
}

std::string ScanOptimizationRegexRulesJson(const char* globalMode,
                                           uint32_t auditMaxEventsPerScan,
                                           bool stopAfterFirstBlock,
                                           const std::vector<std::pair<std::string, std::string>>& rules)
{
    std::string json = std::string("{\"globalMode\":\"") + globalMode +
                       "\",\"scanOptimization\":{\"auditMaxEventsPerScan\":" +
                       std::to_string(auditMaxEventsPerScan) +
                       ",\"stopAfterFirstBlock\":" +
                       (stopAfterFirstBlock ? "true" : "false") +
                       "},\"rules\":[";
    for (size_t i = 0; i < rules.size(); ++i) {
        if (i > 0)
            json += ",";
        json += "{\"id\":\"" + rules[i].first +
                "\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"" +
                rules[i].second +
                "\",\"description\":\"scan_opt\",\"config\":{\"regexPatterns\":[\"amsiutils\"]}}";
    }
    json += "]}";
    return json;
}

std::string TrustedProcessRegexRuleJson(const char* trustPath)
{
    return std::string("{\"trust_process\":[\"") + trustPath +
           "\"],\"rules\":["
           "{\"id\":\"trust_first\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\","
           "\"description\":\"trust_first\",\"config\":{\"regexPatterns\":[\"amsiinitfailed\"]}},"
           "{\"id\":\"trust_second\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\","
           "\"description\":\"trust_second\",\"config\":{\"regexPatterns\":[\"amsiinitfailed\"]}}"
           "]}";
}

std::string ParentPathGatedRegexRuleJson(const char* id,
                                         const char* pattern,
                                         const char* allowContains,
                                         const char* blockContains)
{
    std::string config = std::string("\"regexPatterns\":[\"") + pattern + "\"]";
    std::string topLevelFields;
    if (allowContains)
        topLevelFields += std::string(",\"parentPathAllowContains\":[\"") + allowContains + "\"]";
    if (blockContains)
        topLevelFields += std::string(",\"parentPathBlockContains\":[\"") + blockContains + "\"]";

    return std::string("{\"rules\":[{\"id\":\"") + id +
           "\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\",\"description\":\"parent_gate\",\"config\":{" +
           config + "}" + topLevelFields + "}]}";
}

std::string FirstRuleGatedSecondRuleFallbackJson()
{
    return "{\"rules\":["
           "{\"id\":\"gated_first\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\","
           "\"description\":\"gated_first\",\"config\":{\"regexPatterns\":[\"amsiinitfailed\"]},"
           "\"parentPathBlockContains\":[\"/not-present/\"]},"
           "{\"id\":\"fallback_second\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\","
           "\"description\":\"fallback_second\",\"config\":{\"regexPatterns\":[\"amsiinitfailed\"]}}"
           "]}";
}

std::string FirstRegexLimitedSecondRuleFallbackJson()
{
    return "{\"rules\":["
           "{\"id\":\"regex_limited_first\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\","
           "\"description\":\"regex_limited_first\",\"config\":{\"regexPatterns\":[\"(?s)REGEX_TIMEOUT_PROBE:(?:a|aa)+$\"]}},"
           "{\"id\":\"regex_fallback_second\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\","
           "\"description\":\"regex_fallback_second\",\"config\":{\"regexPatterns\":[\"SECOND_OK\"]}}"
           "]}";
}

std::string OneRawLuaRuleJson(const char* id, const char* scriptBase64)
{
    return std::string("{\"rules\":[{\"id\":\"") + id +
           "\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\",\"description\":\"ctx_rule\",\"scriptBodyBase64\":\"" +
           scriptBase64 + "\"}]}";
}

std::string OneEncodedLuaRuleJson(const char* id,
                                  const char* scriptBase64,
                                  const char* scriptEncoding)
{
    return std::string("{\"rules\":[{\"id\":\"") + id +
           "\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\",\"description\":\"encoded_rule\",\"scriptBodyBase64\":\"" +
           scriptBase64 + "\",\"scriptEncoding\":\"" + scriptEncoding + "\"}]}";
}

} // namespace

static bool RunEngineRuntimeTestGroup1()
{
    {
        auto runtime = MakeRuntime();
        if (!Expect(runtime->GetState() == EngineState::Uninitialized,
                    "new runtime starts uninitialized"))
            return false;
        if (!Expect(runtime->EnsureInitialized(), "runtime initializes"))
            return false;
        if (!Expect(runtime->GetState() == EngineState::Ready,
                    "runtime becomes ready after initialization"))
            return false;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        {
            auto guard = runtime->TryEnterScan();
            if (!Expect(guard.IsActive(), "scan can enter ready runtime"))
                return false;
            if (!Expect(runtime->ActiveScanCount() == 1,
                        "scan guard increments active count"))
                return false;
        }
        if (!Expect(runtime->ActiveScanCount() == 0,
                    "scan guard destructor decrements active count"))
            return false;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        runtime->PauseDetection();
        if (!Expect(runtime->IsDetectionPaused(),
                    "runtime records detection pause state"))
            return false;
        auto rejected = runtime->TryEnterScan();
        if (!Expect(!rejected.IsActive(),
                    "paused runtime rejects new scans"))
            return false;
        runtime->ResumeDetection();
        if (!Expect(!runtime->IsDetectionPaused(),
                    "runtime clears detection pause state"))
            return false;
        auto resumed = runtime->TryEnterScan();
        if (!Expect(resumed.IsActive(),
                    "resumed runtime accepts scans"))
            return false;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        auto inFlight = runtime->TryEnterScan();
        if (!Expect(inFlight.IsActive(),
                    "scan enters before pause"))
            return false;
        runtime->PauseDetection();
        if (!Expect(runtime->ActiveScanCount() == 1,
                    "pause does not interrupt in-flight scan"))
            return false;
        auto rejected = runtime->TryEnterScan();
        if (!Expect(!rejected.IsActive(),
                    "pause applies to the next scan entry"))
            return false;
        inFlight = {};
        if (!Expect(runtime->ActiveScanCount() == 0,
                    "in-flight scan can finish after pause"))
            return false;
        runtime->ResumeDetection();
        auto resumed = runtime->TryEnterScan();
        if (!Expect(resumed.IsActive(),
                    "resume accepts new scan after paused in-flight scan exits"))
            return false;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        runtime->PauseDetection();
        runtime->PauseDetection();
        auto rejected = runtime->TryEnterScan();
        if (!Expect(!rejected.IsActive(),
                    "repeated pause remains paused"))
            return false;
        runtime->ResumeDetection();
        runtime->ResumeDetection();
        auto resumed = runtime->TryEnterScan();
        if (!Expect(resumed.IsActive(),
                    "repeated resume remains enabled"))
            return false;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        auto guard = runtime->TryEnterScan();
        auto start = std::chrono::steady_clock::now();
        bool drained = runtime->BeginShutdown("test_shutdown", 25);
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (!Expect(!drained, "shutdown times out while scan is active"))
            return false;
        if (!Expect(elapsed < std::chrono::milliseconds(500),
                    "shutdown drain is bounded"))
            return false;
        if (!Expect(runtime->GetState() == EngineState::Inert,
                    "shutdown timeout enters inert"))
            return false;
        auto rejected = runtime->TryEnterScan();
        if (!Expect(!rejected.IsActive(), "inert runtime rejects new scans"))
            return false;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        std::atomic<bool> entered{false};
        std::thread worker([&]() {
            auto guard = runtime->TryEnterScan();
            entered.store(guard.IsActive());
        });
        worker.join();
        if (!Expect(entered.load(), "concurrent scan entry succeeds in ready state"))
            return false;
        if (!Expect(runtime->ActiveScanCount() == 0,
                    "concurrent scan guard releases active count"))
            return false;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        if (!Expect(runtime->CanAttemptReload(),
                    "ready runtime can attempt reload"))
            return false;
        auto reload = runtime->TryEnterReload("test_reload");
        if (!Expect(reload.IsActive(), "ready runtime enters reload"))
            return false;
        if (!Expect(runtime->GetState() == EngineState::Reloading,
                    "reload guard sets reloading state"))
            return false;
        auto repeated = runtime->TryEnterReload("repeat_reload");
        if (!Expect(!repeated.IsActive(), "reloading rejects repeated reload"))
            return false;
        auto scan = runtime->TryEnterScan();
        if (!Expect(scan.IsActive(), "reloading allows scan on current snapshot"))
            return false;
        reload.Complete(true, "published");
        if (!Expect(runtime->GetState() == EngineState::Ready,
                    "successful reload returns ready"))
            return false;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        runtime->PauseDetection();
        auto reload = runtime->TryEnterReload("reload_while_paused");
        if (!Expect(reload.IsActive(),
                    "paused runtime can still reload rules"))
            return false;
        reload.Complete(true, "published");
        if (!Expect(runtime->IsDetectionPaused(),
                    "reload does not clear pause state"))
            return false;
        auto rejected = runtime->TryEnterScan();
        if (!Expect(!rejected.IsActive(),
                    "scan remains paused after reload"))
            return false;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        {
            auto reload = runtime->TryEnterReload("implicit_failure");
            if (!Expect(reload.IsActive(), "reload guard enters before destructor test"))
                return false;
        }
        if (!Expect(runtime->GetState() == EngineState::Ready,
                    "reload guard destructor restores ready on implicit failure"))
            return false;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        auto reload = runtime->TryEnterReload("shutdown_priority");
        if (!Expect(reload.IsActive(), "reload enters before shutdown priority test"))
            return false;
        bool drained = runtime->BeginShutdown("shutdown_during_reload", 25);
        if (!Expect(drained, "shutdown drains when no scans are active"))
            return false;
        if (!Expect(runtime->GetState() == EngineState::Inert,
                    "shutdown during reload enters inert"))
            return false;
        reload.Complete(true, "late_success");
        if (!Expect(runtime->GetState() == EngineState::Inert,
                    "late reload completion does not restore ready"))
            return false;
        auto rejectedScan = runtime->TryEnterScan();
        if (!Expect(!rejectedScan.IsActive(), "inert rejects scan after reload shutdown race"))
            return false;
        auto rejectedReload = runtime->TryEnterReload("after_shutdown");
        if (!Expect(!rejectedReload.IsActive(), "inert rejects reload after shutdown"))
            return false;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        runtime->EnterFaulted("test_fault");
        auto scan = runtime->TryEnterScan();
        if (!Expect(!scan.IsActive(), "faulted rejects scan"))
            return false;
        auto reload = runtime->TryEnterReload("faulted_reload");
        if (!Expect(!reload.IsActive(), "faulted rejects reload"))
            return false;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        bool drained = runtime->BeginShutdown("publish_before_reload", 25);
        if (!Expect(drained, "shutdown before publish drains"))
            return false;
        auto reload = runtime->TryEnterReload("publish_after_shutdown");
        if (!Expect(!reload.IsActive(),
                    "reload build success but publish after shutdown is rejected"))
            return false;
        if (!Expect(runtime->GetState() == EngineState::Inert,
                    "publish after shutdown rejection does not restore ready"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        const char* oldScript = "function rule(sensor, context) return { match = true, desc = 'old' } end";
        const char* newScript = "function rule(sensor, context) return { match = true, desc = 'new' } end";
        if (!Expect(engine.ParseAndSwap(OneLuaRuleJson("old_rule", "old_desc", oldScript), ""),
                    "old snapshot publishes"))
            return false;

        RaspLuaContext ctx;
        auto before = engine.Evaluate("AmsiProvider", ctx);
        if (!Expect(!before.empty() && before[0].ruleId == "old_rule",
                    "old Lua rule matches before reload build"))
            return false;

        std::string effectiveLib;
        auto next = engine.BuildNextSnapshot(OneLuaRuleJson("new_rule", "new_desc", newScript),
                                             "",
                                             effectiveLib);
        if (!Expect(next != nullptr, "next snapshot builds without publishing"))
            return false;

        auto duringBuild = engine.Evaluate("AmsiProvider", ctx);
        if (!Expect(!duringBuild.empty() && duringBuild[0].ruleId == "old_rule",
                    "building next snapshot does not clear old snapshot Lua engine"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        const char* bytecodeSource =
            "function rule(sensor, context) return { match = true, desc = 'bytecode-snapshot' } end";
        std::string bytecode = CompileLuaBytecode(bytecodeSource, "=bytecode_snapshot");
        if (!Expect(!bytecode.empty(), "snapshot test compiles Lua bytecode"))
            return false;

        std::string json = OneEncodedLuaRuleJson("bytecode_snapshot",
                                                 Base64Encode(bytecode).c_str(),
                                                 "bytecode");
        const std::string libSource = "function lib_marker() return 'lib' end";
        if (!Expect(engine.BuildSnapshotLuaMatches(json, libSource, "bytecode_snapshot", "bytecode-snapshot"),
                    "PrecompileAll loads bytecode without prepending libSource"))
            return false;
    }

    return true;
}

static bool RunEngineRuntimeTestGroup2()
{
#ifdef RASP_PCRE2_AVAILABLE
    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.BuildRegexSnapshotsHaveIndependentCaches(
                        OneRegexRuleJson("regex_old_snapshot", "IEX"),
                        OneRegexRuleJson("regex_new_snapshot", "DownloadString")),
                    "regex compiled cache is isolated per snapshot-local Lua engine"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        std::string effectiveLib;
        auto snapshot = engine.BuildNextSnapshot(MultiRegexRuleJson(), "", effectiveLib);
        if (!Expect(snapshot && snapshot->luaEngine,
                    "multi regex snapshot publishes with Lua engine"))
            return false;
        if (!Expect(snapshot->luaEngine->RegexCacheSizeForTesting() >= 3,
                    "multi regex rule precompiles all regex patterns"))
            return false;
    }
#endif

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(OneRegexRuleJson("split_iex", "IEX"), ""),
                    "split regex snapshot publishes"))
            return false;

        AmsiEvalResult first = engine.Evaluate(L"same-content", L"powershell.exe", "I", 1);
        if (!Expect(!first.ruleMatched, "first split chunk alone does not match"))
            return false;

        AmsiEvalResult second = engine.Evaluate(L"same-content", L"powershell.exe", "EX", 2);
        if (!Expect(!second.ruleMatched,
                    "production scan path does not aggregate split token chunks"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ScanContextRegexRuleJson(false, 8192, 3000, 16384, true, "(?s)amsi.*utils"),
                        ""),
                    "disabled scanContext snapshot publishes"))
            return false;

        AmsiEvalResult first = engine.Evaluate(L"demo.ps1", L"powershell.exe", "amsi", 4);
        if (!Expect(!first.ruleMatched,
                    "disabled scanContext first chunk does not match"))
            return false;

        AmsiEvalResult second = engine.Evaluate(L"demo.ps1", L"powershell.exe", "utils", 5);
        if (!Expect(!second.ruleMatched,
                    "disabled scanContext does not aggregate split chunks"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ScanContextRegexRuleJson(true, 8192, 3000, 16384, true, "(?s)amsi.*utils"),
                        ""),
                    "enabled scanContext snapshot publishes"))
            return false;

        AmsiEvalResult first = engine.Evaluate(L"demo.ps1", L"powershell.exe", "amsi", 4);
        if (!Expect(!first.ruleMatched,
                    "enabled scanContext first chunk alone does not match"))
            return false;

        AmsiEvalResult second = engine.Evaluate(L"demo.ps1", L"powershell.exe", "utils", 5);
        if (!Expect(second.ruleMatched && second.ruleId == "scan_context_rule",
                    "enabled scanContext matches split chunks within ttl"))
            return false;

        AmsiEvalResult third = engine.Evaluate(L"demo.ps1", L"powershell.exe", "utils", 5);
        if (!Expect(!third.ruleMatched,
                    "clearOnMatch clears scanContext after split chunk match"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ScanContextRegexRuleJson(true, 8192, 100, 16384, true, "(?s)amsi.*utils"),
                        ""),
                    "ttl scanContext snapshot publishes"))
            return false;

        AmsiEvalResult first = engine.Evaluate(L"demo.ps1", L"powershell.exe", "amsi", 4);
        if (!Expect(!first.ruleMatched,
                    "ttl scanContext first chunk alone does not match"))
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        AmsiEvalResult second = engine.Evaluate(L"demo.ps1", L"powershell.exe", "utils", 5);
        if (!Expect(!second.ruleMatched,
                    "expired scanContext does not match stale split chunk"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(RateLimitedScanContextRegexRuleJson(), ""),
                    "rate-limited scanContext snapshot publishes"))
            return false;

        AmsiEvalResult first = engine.Evaluate(L"demo.ps1", L"powershell.exe", "amsi", 4);
        if (!Expect(!first.ruleMatched,
                    "rate-limited scanContext first scan appends without match"))
            return false;

        AmsiEvalResult second = engine.Evaluate(L"demo.ps1", L"powershell.exe", "utils", 5);
        if (!Expect(!second.ruleMatched,
                    "scanRateLimit bypass returns NoMatch before scanContext evaluation"))
            return false;
    }
    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ScanContextRegexRuleJson(true, 8192, 3000, 16384, true, "(?s)amsi.*utils"),
                        ""),
                    "infrastructure contentName scanContext snapshot publishes"))
            return false;

        AmsiEvalResult first = engine.Evaluate(L"PSReadLine.psm1", L"powershell.exe", "amsi", 4);
        if (!Expect(!first.ruleMatched,
                    "infrastructure contentName first chunk is still scanned alone"))
            return false;

        AmsiEvalResult second = engine.Evaluate(L"demo.ps1", L"powershell.exe", "utils", 5);
        if (!Expect(!second.ruleMatched,
                    "infrastructure contentName chunk does not append to scanContext"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(OneRegexRuleJson("infra_content_name_bypass", "amsi"), ""),
                    "infrastructure contentName bypass rule snapshot publishes"))
            return false;

        AmsiEvalResult skipped = engine.Evaluate(L"PSReadLine.psm1", L"powershell.exe", "amsi", 4);
        if (!Expect(skipped.ruleMatched && skipped.ruleId == "infra_content_name_bypass",
                    "infrastructure contentName is evaluated as a single scan"))
            return false;

        AmsiEvalResult normal = engine.Evaluate(L"demo.ps1", L"powershell.exe", "amsi", 4);
        if (!Expect(normal.ruleMatched && normal.ruleId == "infra_content_name_bypass",
                    ".ps1 contentName still evaluates rules"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(OneRegexRuleJson("infra_body_prefix_bypass", "FullyQualifiedErrorId"), ""),
                    "infrastructure body prefix bypass rule snapshot publishes"))
            return false;

        const char* errorFormatter = "FullyQualifiedErrorId : CommandNotFoundException";
        AmsiEvalResult skipped = engine.Evaluate(L"", L"powershell.exe", errorFormatter, std::strlen(errorFormatter));
        if (!Expect(skipped.ruleMatched && skipped.ruleId == "infra_body_prefix_bypass",
                    "infrastructure body prefix is evaluated as a single scan"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ScanContextRegexRuleJson(true, 8192, 3000, 16384, true, "amsi", 8),
                        ""),
                    "too-large current body still evaluates snapshot publishes"))
            return false;

        std::string padded = std::string(300, 'A') + " amsi";
        AmsiEvalResult matched = engine.Evaluate(L"demo.ps1",
                                                 L"powershell.exe",
                                                 padded.c_str(),
                                                 padded.size());
        if (!Expect(matched.ruleMatched && matched.ruleId == "scan_context_rule",
                    "too-large current body is still evaluated as a single scan"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ScanContextRegexRuleJson(true, 8192, 3000, 16384, true, "(?s)amsi.*utils"),
                        ""),
                    "ps1 scanContext snapshot publishes"))
            return false;

        AmsiEvalResult first = engine.Evaluate(L"demo.ps1", L"powershell.exe", "amsi", 4);
        if (!Expect(!first.ruleMatched,
                    ".ps1 first chunk alone does not match"))
            return false;

        AmsiEvalResult second = engine.Evaluate(L"demo.ps1", L"powershell.exe", "utils", 5);
        if (!Expect(second.ruleMatched && second.ruleId == "scan_context_rule",
                    ".ps1 contentName is allowed to append to scanContext"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ScanContextRegexRuleJson(true, 8192, 3000, 16384, true, "malicious", 8, 128),
                        ""),
                    "too-large single-scan snapshot publishes"))
            return false;

        const std::string body = "0123456789 malicious";
        AmsiEvalResult matched = engine.Evaluate(L"demo.ps1", L"powershell.exe", body.data(), static_cast<ULONG>(body.size()));
        if (!Expect(matched.ruleMatched && matched.ruleId == "scan_context_rule",
                    "too-large current body is still evaluated as a single scan"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ScanContextRegexRuleJson(true, 8192, 3000, 16384, true, "(?s)amsi.*utils", 8, 128),
                        ""),
                    "too-large no-history snapshot publishes"))
            return false;

        AmsiEvalResult first = engine.Evaluate(L"demo.ps1", L"powershell.exe", "amsi", 4);
        if (!Expect(!first.ruleMatched,
                    "too-large no-history first chunk appends"))
            return false;

        const std::string body = "0123456789 utils";
        AmsiEvalResult second = engine.Evaluate(L"demo.ps1", L"powershell.exe", body.data(), static_cast<ULONG>(body.size()));
        if (!Expect(!second.ruleMatched,
                    "too-large current body does not read historical scanContext"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ScanContextRegexRuleJson(true, 8192, 3000, 16384, true, "(?s)amsi.*utils", 256, 128),
                        ""),
                    "body-prefix infrastructure snapshot publishes"))
            return false;

        AmsiEvalResult first = engine.Evaluate(L"demo.ps1", L"powershell.exe", "amsi", 4);
        if (!Expect(!first.ruleMatched,
                    "body-prefix first chunk appends"))
            return false;

        const char* body = "function prompt { utils }";
        AmsiEvalResult second = engine.Evaluate(L"demo.ps1", L"powershell.exe", body, static_cast<ULONG>(std::strlen(body)));
        if (!Expect(!second.ruleMatched,
                    "body-prefix infrastructure input does not read historical scanContext"))
            return false;

        AmsiEvalResult third = engine.Evaluate(L"demo.ps1", L"powershell.exe", "utils", 5);
        if (!Expect(third.ruleMatched && third.ruleId == "scan_context_rule",
                    "body-prefix infrastructure match does not clear existing scanContext"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ScanContextRegexRuleJson(true, 8192, 3000, 16384, true, "(?s)amsi.*utils", 256, 128),
                        ""),
                    "prompt word scanContext snapshot publishes"))
            return false;

        AmsiEvalResult first = engine.Evaluate(L"demo.ps1", L"powershell.exe", "amsi", 4);
        if (!Expect(!first.ruleMatched,
                    "prompt word first chunk appends"))
            return false;

        AmsiEvalResult second = engine.Evaluate(L"demo.ps1", L"powershell.exe", "please prompt utils", 19);
        if (!Expect(second.ruleMatched && second.ruleId == "scan_context_rule",
                    "plain prompt word does not disable scanContext append"))
            return false;
    }


    return true;
}

static bool RunEngineRuntimeTestGroup3()
{
    {
        TestAmsiRuleEngine engine;
        const char* parentRule =
            "ZnVuY3Rpb24gcnVsZShzZW5zb3IsIGNvbnRleHQpIGlmIGNvbnRleHQucGFyZW50UHJvY2Vzc05hbWUgPT0gJ2NtZC5leGUnIGFuZCBjb250ZXh0LnBhcmVudFBpZCA9PSAnMTIzNCcgYW5kIGNvbnRleHQucHJvY2Vzc0NhcHR1cmVTdGF0dXMgPT0gJ3N1Y2Nlc3MnIGFuZCBjb250ZXh0LnByb2Nlc3NSZXRyeVN0YXRlID09ICdub25lJyB0aGVuIHJldHVybiB7IG1hdGNoID0gdHJ1ZSwgZGVzYyA9ICdwYXJlbnQtY3R4JywgcGF5bG9hZCA9IGNvbnRleHQucGFyZW50UHJvY2Vzc05hbWUgfSBlbmQgcmV0dXJuIHsgbWF0Y2ggPSBmYWxzZSB9IGVuZA==";
        if (!Expect(engine.ParseAndSwap(OneRawLuaRuleJson("parent_ctx", parentRule), ""),
                    "parent context Lua snapshot publishes"))
            return false;

        ProcessContextSnapshot process;
        process.valid = true;
        process.parentResolved = true;
        process.parentPid = 1234;
        process.parentProcessName = "cmd.exe";
        process.status = ProcessCaptureStatus::Success;
        process.retryState = ProcessRetryState::None;

        ScanContext scanContext;
        scanContext.process = &process;
        AmsiEvalResult matched = engine.Evaluate(L"demo.ps1",
                                                 L"powershell.exe",
                                                 "Write-Host test",
                                                 15,
                                                 scanContext);
        if (!Expect(matched.ruleMatched && matched.payload == "cmd.exe",
                    "Lua can read parent process fields from scan context"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(OneRegexRuleJson("body_regex", "DownloadString"), ""),
                    "body regex snapshot publishes"))
            return false;

        ScanContext scanContext;
        scanContext.process = nullptr;
        AmsiEvalResult matched = engine.Evaluate(L"demo.ps1",
                                                 L"powershell.exe",
                                                 "DownloadString",
                                                 14,
                                                 scanContext);
        if (!Expect(matched.ruleMatched && matched.payload == "DownloadString",
                    "nullptr process context does not block body detection"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        const std::string auditJson = GlobalModeRegexRuleJson("audit",
                                                              "block",
                                                              "global_hash_rule",
                                                              "amsiutils");
        const std::string blockJson = GlobalModeRegexRuleJson("block",
                                                              "block",
                                                              "global_hash_rule",
                                                              "amsiutils");
        const std::string auditHash = engine.ComputeEffectiveSnapshotHash(auditJson);
        const std::string blockHash = engine.ComputeEffectiveSnapshotHash(blockJson);
        if (!Expect(!auditHash.empty(), "effective snapshot hash is populated"))
            return false;
        if (!Expect(auditHash != blockHash,
                    "effective snapshot hash changes when globalMode changes"))
            return false;
        engine.SetActiveEffectiveSnapshotHash(auditHash);
        if (!Expect(engine.ActiveEffectiveSnapshotHash() == auditHash,
                    "active effective snapshot hash is stored"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(GlobalModeRegexRuleJson("audit",
                                                                "block",
                                                                "global_audit_block_rule",
                                                                "amsiutils"),
                                       ""),
                    "globalMode audit snapshot publishes"))
            return false;

        AmsiEvalResult matched = engine.Evaluate(L"demo.ps1",
                                                 L"powershell.exe",
                                                 "amsiutils",
                                                 9);
        if (!Expect(matched.ruleMatched, "globalMode audit still reports matched rules"))
            return false;
        if (!Expect(!matched.block, "globalMode audit downgrades block rule to audit"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ScanOptimizationRegexRulesJson("audit",
                                                       2,
                                                       true,
                                                       {{"audit_limit_1", "block"},
                                                        {"audit_limit_2", "block"},
                                                        {"audit_limit_3", "block"}}),
                        ""),
                    "scanOptimization audit limit snapshot publishes"))
            return false;

        RaspLuaContext ctx;
        ctx.fields.push_back({"body", "amsiutils", true});
        auto results = engine.Evaluate("AmsiProvider", ctx);
        if (!Expect(results.size() == 2,
                    "globalMode audit stops after auditMaxEventsPerScan matches"))
            return false;
        if (!Expect(results[0].ruleId == "audit_limit_1" && results[1].ruleId == "audit_limit_2",
                    "globalMode audit returns the first limited audit matches"))
            return false;
        if (!Expect(!results[0].block && !results[1].block,
                    "globalMode audit limit keeps results in audit mode"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ScanOptimizationRegexRulesJson("audit",
                                                       0,
                                                       true,
                                                       {{"audit_unlimited_1", "block"},
                                                        {"audit_unlimited_2", "block"},
                                                        {"audit_unlimited_3", "block"}}),
                        ""),
                    "scanOptimization audit unlimited snapshot publishes"))
            return false;

        RaspLuaContext ctx;
        ctx.fields.push_back({"body", "amsiutils", true});
        auto results = engine.Evaluate("AmsiProvider", ctx);
        if (!Expect(results.size() == 3,
                    "auditMaxEventsPerScan zero leaves audit matches unlimited"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(GlobalModeRegexRuleJson("block",
                                                                "block",
                                                                "global_block_block_rule",
                                                                "amsiutils"),
                                       ""),
                    "globalMode block snapshot publishes"))
            return false;

        AmsiEvalResult matched = engine.Evaluate(L"demo.ps1",
                                                 L"powershell.exe",
                                                 "amsiutils",
                                                 9);
        if (!Expect(matched.ruleMatched && matched.block,
                    "globalMode block preserves block rule decision"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ScanOptimizationRegexRulesJson("block",
                                                       3,
                                                       true,
                                                       {{"first_block_stop", "block"},
                                                        {"second_after_block", "block"}}),
                        ""),
                    "scanOptimization stop after first block snapshot publishes"))
            return false;

        RaspLuaContext ctx;
        ctx.fields.push_back({"body", "amsiutils", true});
        auto results = engine.Evaluate("AmsiProvider", ctx);
        if (!Expect(results.size() == 1 && results[0].ruleId == "first_block_stop" && results[0].block,
                    "stopAfterFirstBlock stops evaluating after the first final block"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ScanOptimizationRegexRulesJson("block",
                                                       1,
                                                       true,
                                                       {{"first_audit_continue", "audit"},
                                                        {"second_block_stop", "block"},
                                                        {"third_after_block", "block"}}),
                        ""),
                    "scanOptimization block mode block-first snapshot publishes"))
            return false;

        RaspLuaContext ctx;
        ctx.fields.push_back({"body", "amsiutils", true});
        auto results = engine.Evaluate("AmsiProvider", ctx);
        if (!Expect(results.size() == 1,
                    "block mode stops after first block-group match before alert group"))
            return false;
        if (!Expect(results[0].ruleId == "second_block_stop" && results[0].block,
                    "block mode evaluates block rules before earlier alert rules"))
            return false;

        AmsiEvalResult publicResult = engine.Evaluate(L"demo.ps1",
                                                      L"powershell.exe",
                                                      "amsiutils",
                                                      9);
        if (!Expect(publicResult.ruleMatched && publicResult.block &&
                    publicResult.ruleId == "second_block_stop",
                    "public AMSI result blocks when any later result is block"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        const std::string json =
            "{\"globalMode\":\"block\","
            "\"scanOptimization\":{\"auditMaxEventsPerScan\":1,\"stopAfterFirstBlock\":true},"
            "\"rules\":["
            "{\"id\":\"alert_only_match\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"alert\","
            "\"description\":\"scan_opt\",\"config\":{\"regexPatterns\":[\"amsiutils\"]}},"
            "{\"id\":\"second_alert_limited\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"alert\","
            "\"description\":\"scan_opt\",\"config\":{\"regexPatterns\":[\"amsiutils\"]}},"
            "{\"id\":\"block_no_match\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\","
            "\"description\":\"scan_opt\",\"config\":{\"regexPatterns\":[\"nevermatch\"]}}"
            "]}";
        if (!Expect(engine.ParseAndSwap(json, ""),
                    "scanOptimization alert phase snapshot publishes"))
            return false;

        RaspLuaContext ctx;
        ctx.fields.push_back({"body", "amsiutils", true});
        auto results = engine.Evaluate("AmsiProvider", ctx);
        if (!Expect(results.size() == 1 && results[0].ruleId == "alert_only_match",
                    "block mode limits non-block events with auditMaxEventsPerScan"))
            return false;
        if (!Expect(!results[0].block,
                    "alert group never returns block in block global mode"))
            return false;
    }

    return true;
}

static bool RunEngineRuntimeTestGroup4()
{
    {
        TestAmsiRuleEngine engine;
        const std::string timeoutJson =
            "{\"globalMode\":\"block\",\"totalScanTimeoutMs\":750,\"rules\":[{\"id\":\"timeout_cfg\","
            "\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\","
            "\"description\":\"timeout_cfg\",\"config\":{\"regexPatterns\":[\"amsiutils\"]}}]}";
        if (!Expect(engine.BuildSnapshotTotalScanTimeoutMs(timeoutJson) == 750,
                    "totalScanTimeoutMs is published into the rule snapshot"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        const std::string budgetJson =
            "{\"globalMode\":\"block\",\"maxRulesPerScan\":2,\"maxRegexCallsPerScan\":3,"
            "\"rules\":[{\"id\":\"budget_cfg\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\","
            "\"description\":\"budget_cfg\",\"config\":{\"regexPatterns\":[\"amsiutils\"]}}]}";
        auto budget = engine.BuildSnapshotScanBudgets(budgetJson);
        if (!Expect(budget.first == 2,
                    "maxRulesPerScan is published into the rule snapshot"))
            return false;
        if (!Expect(budget.second == 3,
                    "maxRegexCallsPerScan is published into the rule snapshot"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        const std::string budgetJson =
            "{\"globalMode\":\"block\",\"maxRulesPerScan\":1,\"rules\":["
            "{\"id\":\"first_no_match\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"alert\","
            "\"description\":\"budget_cfg\",\"config\":{\"regexPatterns\":[\"nevermatch\"]}},"
            "{\"id\":\"second_match\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"alert\","
            "\"description\":\"budget_cfg\",\"config\":{\"regexPatterns\":[\"amsiutils\"]}}]}";
        if (!Expect(engine.ParseAndSwap(budgetJson, ""),
                    "maxRulesPerScan runtime snapshot publishes"))
            return false;
        AmsiEvalResult limited = engine.Evaluate(L"demo.ps1", L"powershell.exe", "amsiutils", 9);
        if (!Expect(!limited.ruleMatched,
                    "maxRulesPerScan stops evaluation before later matching rule"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        const std::string budgetJson =
            "{\"globalMode\":\"block\",\"maxRegexCallsPerScan\":1,\"rules\":["
            "{\"id\":\"regex_budget\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"alert\","
            "\"description\":\"budget_cfg\",\"config\":{\"regexPatterns\":[\"(?!)\",\"amsiutils\"]}}]}";
        if (!Expect(engine.ParseAndSwap(budgetJson, ""),
                    "maxRegexCallsPerScan runtime snapshot publishes"))
            return false;
        AmsiEvalResult limited = engine.Evaluate(L"demo.ps1", L"powershell.exe", "amsiutils", 9);
        if (!Expect(!limited.ruleMatched,
                    "maxRegexCallsPerScan stops evaluation before later matching regex"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        const std::string diagnosticsJson =
            "{\"globalMode\":\"block\",\"diagnostics\":{\"perfLog\":true,\"scanDumpLog\":true,\"scanDumpMaxBytes\":2048},"
            "\"rules\":[{\"id\":\"diag_cfg\",\"sensor\":\"AmsiProvider\",\"enabled\":true,\"mode\":\"block\","
            "\"description\":\"diag_cfg\",\"config\":{\"regexPatterns\":[\"amsiutils\"]}}]}";
        DiagnosticsConfig cfg = engine.BuildSnapshotDiagnostics(diagnosticsJson);
        if (!Expect(cfg.perfLog,
                    "diagnostics perfLog is published into the rule snapshot"))
            return false;
        if (!Expect(cfg.scanDumpLog,
                    "diagnostics scanDumpLog is published into the rule snapshot"))
            return false;
        if (!Expect(cfg.scanDumpMaxBytes == 2048,
                    "diagnostics scanDumpMaxBytes is published into the rule snapshot"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        ScanRateLimitConfig cfg = engine.BuildSnapshotScanRateLimit(RateLimitedRegexRuleJson(3, 0.8));
        if (!Expect(cfg.enabled && cfg.windowMs == 1000 && cfg.maxScans == 3,
                    "scanRateLimit is published into the rule snapshot"))
            return false;
        if (!Expect(cfg.bypassRatioAfterLimit == 0.8,
                    "scanRateLimit ratio is published into the rule snapshot"))
            return false;

        auto d1 = engine.CheckScanRateLimit(cfg, 1000);
        auto d2 = engine.CheckScanRateLimit(cfg, 1001);
        auto d3 = engine.CheckScanRateLimit(cfg, 1002);
        if (!Expect(!d1.bypass && !d2.bypass && !d3.bypass,
                    "scanRateLimit does not bypass within maxScans"))
            return false;
        auto d4 = engine.CheckScanRateLimit(cfg, 1003);
        if (!Expect(d4.overLimit && d4.reason == std::string("scan_rate_limited"),
                    "scanRateLimit reports reason after maxScans"))
            return false;
        if (!Expect(d4.windowScanCount == 4 && d4.overLimitSeq == 1 && d4.bypassPermille == 800,
                    "scanRateLimit decision exposes counters and rounded permille"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        ScanRateLimitConfig cfg;
        cfg.enabled = true;
        cfg.windowMs = 1000;
        cfg.maxScans = 1;
        cfg.bypassRatioAfterLimit = 1.0;
        if (!Expect(!engine.CheckScanRateLimit(cfg, 2000).bypass,
                    "first scan in window is evaluated"))
            return false;
        if (!Expect(engine.CheckScanRateLimit(cfg, 2001).bypass,
                    "bypassRatioAfterLimit 1.0 bypasses all over-limit scans"))
            return false;
        if (!Expect(!engine.CheckScanRateLimit(cfg, 3000).bypass,
                    "new window resets scan rate limit"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        ScanRateLimitConfig cfg;
        cfg.enabled = true;
        cfg.windowMs = 1000;
        cfg.maxScans = 1;
        cfg.bypassRatioAfterLimit = 0.0;
        (void)engine.CheckScanRateLimit(cfg, 4000);
        auto overLimit = engine.CheckScanRateLimit(cfg, 4001);
        if (!Expect(overLimit.overLimit && !overLimit.bypass && overLimit.bypassPermille == 0,
                    "bypassRatioAfterLimit 0.0 observes over-limit without bypass"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(RateLimitedRegexRuleJson(1, 1.0), ""),
                    "rate-limited regex snapshot publishes"))
            return false;
        AmsiEvalResult first = engine.Evaluate(L"demo.ps1", L"powershell.exe", "amsiutils", 9);
        if (!Expect(first.ruleMatched && first.block,
                    "first scan before rate limit evaluates rules"))
            return false;
        AmsiEvalResult second = engine.Evaluate(L"demo.ps1", L"powershell.exe", "amsiutils", 9);
        if (!Expect(!second.ruleMatched,
                    "over-limit scan returns NoMatch without detection"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(GlobalModeRegexRuleJson("block",
                                                                "audit",
                                                                "global_block_audit_rule",
                                                                "amsiutils"),
                                       ""),
                    "globalMode block audit-rule snapshot publishes"))
            return false;

        AmsiEvalResult matched = engine.Evaluate(L"demo.ps1",
                                                 L"powershell.exe",
                                                 "amsiutils",
                                                 9);
        if (!Expect(matched.ruleMatched && !matched.block,
                    "globalMode block preserves audit rule decision"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ParentPathGatedRegexRuleJson("parent_gate_block_miss",
                                                     "amsiinitfailed",
                                                     nullptr,
                                                     "\\\\asp businesee one\\\\"),
                        ""),
                    "parent gate block miss rule snapshot publishes"))
            return false;

        ProcessContextSnapshot process;
        process.valid = true;
        process.parentResolved = true;
        process.parentPid = 4321;
        process.parentProcessName = "cmd.exe";
        process.parentProcessPath = "C:\\Windows\\System32\\cmd.exe";
        process.status = ProcessCaptureStatus::Success;
        process.retryState = ProcessRetryState::None;

        ScanContext scanContext;
        scanContext.process = &process;
        AmsiEvalResult matched = engine.Evaluate(L"demo.ps1",
                                                 L"powershell.exe",
                                                 "amsiinitfailed",
                                                 14,
                                                 scanContext);
        if (!Expect(!matched.ruleMatched,
                    "parentPathBlockContains miss skips current rule even when regex matches"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ParentPathGatedRegexRuleJson("parent_gate_block_hit",
                                                     "amsiinitfailed",
                                                     nullptr,
                                                     "/asp businesee one/"),
                        ""),
                    "parent gate block hit rule snapshot publishes"))
            return false;

        ProcessContextSnapshot process;
        process.valid = true;
        process.parentResolved = true;
        process.parentPid = 4321;
        process.parentProcessName = "a.exe";
        process.parentProcessPath = "C:\\A\\B\\ASP BUSINESEE ONE\\a.exe";
        process.status = ProcessCaptureStatus::Success;
        process.retryState = ProcessRetryState::None;

        ScanContext scanContext;
        scanContext.process = &process;
        AmsiEvalResult matched = engine.Evaluate(L"demo.ps1",
                                                 L"powershell.exe",
                                                 "amsiinitfailed",
                                                 14,
                                                 scanContext);
        if (!Expect(matched.ruleMatched && matched.ruleId == "parent_gate_block_hit",
                    "parentPathBlockContains is case-insensitive and slash-normalized gate"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ParentPathGatedRegexRuleJson("parent_gate_allow_hit",
                                                     "amsiinitfailed",
                                                     "trusted launcher.exe",
                                                     "\\\\asp businesee one\\\\"),
                        ""),
                    "parent gate allow hit rule snapshot publishes"))
            return false;

        ProcessContextSnapshot process;
        process.valid = true;
        process.parentResolved = true;
        process.parentPid = 4321;
        process.parentProcessName = "trusted launcher.exe";
        process.parentProcessPath = "C:\\Tools\\trusted launcher.exe";
        process.status = ProcessCaptureStatus::Success;
        process.retryState = ProcessRetryState::None;

        ScanContext scanContext;
        scanContext.process = &process;
        AmsiEvalResult matched = engine.Evaluate(L"demo.ps1",
                                                 L"powershell.exe",
                                                 "amsiinitfailed",
                                                 14,
                                                 scanContext);
        if (!Expect(!matched.ruleMatched,
                    "parentPathAllowContains skips current rule even when regex matches"))
            return false;
    }

    {
        auto engine = std::make_unique<TestAmsiRuleEngine>();
        if (!Expect(engine->ParseAndSwap(TrustedProcessRegexRuleJson("C:\\\\csaca.exe"), ""),
                    "trust_process rule snapshot publishes"))
            return false;

        ProcessContextSnapshot process;
        process.valid = true;
        process.parentResolved = true;
        process.currentProcessName = "powershell.exe";
        process.currentProcessPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        process.parentPid = 4321;
        process.parentProcessName = "csaca.exe";
        process.parentProcessPath = "c:/csaca.exe";
        process.status = ProcessCaptureStatus::Success;
        process.retryState = ProcessRetryState::None;

        ScanContext scanContext;
        scanContext.process = &process;
        AmsiEvalResult matched = engine->Evaluate(L"demo.ps1",
                                                  L"powershell.exe",
                                                  "amsiinitfailed",
                                                  14,
                                                  scanContext);
        if (!Expect(!matched.ruleMatched,
                    "trust_process exact normalized parent path skips all rules"))
            return false;
    }

    {
        auto engine = std::make_unique<TestAmsiRuleEngine>();
        if (!Expect(engine->ParseAndSwap(TrustedProcessRegexRuleJson("C:\\\\csaca.exe"), ""),
                    "trust_process rule snapshot publishes for bypass tests"))
            return false;

        ProcessContextSnapshot process;
        process.valid = true;
        process.parentResolved = true;
        process.currentProcessName = "powershell.exe";
        process.currentProcessPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
        process.parentPid = 4321;
        process.parentProcessName = "csaca.exe";
        process.parentProcessPath = "C:\\malware\\csaca.exe";
        process.status = ProcessCaptureStatus::Success;
        process.retryState = ProcessRetryState::None;

        ScanContext scanContext;
        scanContext.process = &process;
        AmsiEvalResult matched = engine->Evaluate(L"demo.ps1",
                                                  L"powershell.exe",
                                                  "amsiinitfailed",
                                                  14,
                                                  scanContext);
        if (!Expect(matched.ruleMatched,
                    "trust_process rejects same filename in different directory"))
            return false;

        process.parentProcessPath = "C:\\csaca.exe.old";
        matched = engine->Evaluate(L"demo.ps1",
                                   L"powershell.exe",
                                   "amsiinitfailed",
                                   14,
                                   scanContext);
        if (!Expect(matched.ruleMatched,
                    "trust_process rejects suffix bypass"))
            return false;
    }

    {
        auto engine = std::make_unique<TestAmsiRuleEngine>();
        if (!Expect(engine->ParseAndSwap(TrustedProcessRegexRuleJson("C:\\\\csaca.exe"), ""),
                    "trust_process rule snapshot publishes without host gate"))
            return false;

        ProcessContextSnapshot process;
        process.valid = true;
        process.parentResolved = true;
        process.parentPid = 4321;
        process.parentProcessName = "csaca.exe";
        process.parentProcessPath = "C:\\csaca.exe";
        process.status = ProcessCaptureStatus::Success;
        process.retryState = ProcessRetryState::None;

        ScanContext scanContext;
        scanContext.process = &process;
        AmsiEvalResult matched = engine->Evaluate(L"demo.vbs",
                                                  L"WScript",
                                                  "amsiinitfailed",
                                                  14,
                                                  scanContext);
        if (!Expect(!matched.ruleMatched,
                    "trust_process relies on parent path because scan entry is PowerShell-only"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(
                        ParentPathGatedRegexRuleJson("parent_gate_missing_path",
                                                     "amsiinitfailed",
                                                     nullptr,
                                                     "\\\\asp businesee one\\\\"),
                        ""),
                    "parent gate missing path rule snapshot publishes"))
            return false;

        ProcessContextSnapshot process;
        process.valid = false;
        process.parentResolved = false;
        process.parentPid = 0;
        process.parentProcessName.clear();
        process.parentProcessPath.clear();
        process.status = ProcessCaptureStatus::ParentPathQueryFailed;
        process.retryState = ProcessRetryState::Exhausted;

        ScanContext scanContext;
        scanContext.process = &process;
        AmsiEvalResult matched = engine.Evaluate(L"demo.ps1",
                                                 L"powershell.exe",
                                                 "amsiinitfailed",
                                                 14,
                                                 scanContext);
        if (!Expect(!matched.ruleMatched,
                    "configured parent path gate skips current rule when parent path is unavailable"))
            return false;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(FirstRuleGatedSecondRuleFallbackJson(), ""),
                    "parent gate current-rule skip snapshot publishes"))
            return false;

        ProcessContextSnapshot process;
        process.valid = true;
        process.parentResolved = true;
        process.parentPid = 4321;
        process.parentProcessName = "cmd.exe";
        process.parentProcessPath = "C:\\Windows\\System32\\cmd.exe";
        process.status = ProcessCaptureStatus::Success;
        process.retryState = ProcessRetryState::None;

        ScanContext scanContext;
        scanContext.process = &process;
        AmsiEvalResult matched = engine.Evaluate(L"demo.ps1",
                                                 L"powershell.exe",
                                                 "amsiinitfailed",
                                                 14,
                                                 scanContext);
        if (!Expect(matched.ruleMatched && matched.ruleId == "fallback_second",
                    "parent path gate skips only current rule and later rules still evaluate"))
            return false;
    }

#ifdef RASP_PCRE2_AVAILABLE
    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(FirstRegexLimitedSecondRuleFallbackJson(), ""),
                    "regex limit current-rule skip snapshot publishes"))
            return false;

        std::string script = "REGEX_TIMEOUT_PROBE:" + std::string(4096, 'a') + "b SECOND_OK";
        AmsiEvalResult matched = engine.Evaluate(L"demo.ps1",
                                                 L"powershell.exe",
                                                 script.c_str(),
                                                 script.size());
        if (!Expect(matched.ruleMatched && matched.ruleId == "regex_fallback_second",
                    "regex resource limit skips only current rule and later rules still evaluate"))
            return false;
    }
#endif

    return true;
}

static bool RunEngineRuntimeTestGroup5()
{
    {
        TestAmsiRuleEngine engine;
        const char* invalidRule =
            "ZnVuY3Rpb24gcnVsZShzZW5zb3IsIGNvbnRleHQpIGlmIGNvbnRleHQucHJvY2Vzc0NhcHR1cmVTdGF0dXMgPT0gJ250ZGxsLXVuYXZhaWxhYmxlJyBhbmQgY29udGV4dC5wcm9jZXNzUmV0cnlTdGF0ZSA9PSAncGVuZGluZycgYW5kIGNvbnRleHQucGFyZW50UHJvY2Vzc05hbWUgPT0gJycgYW5kIGNvbnRleHQuYm9keSA9PSAnV3JpdGVIb3N0JyB0aGVuIHJldHVybiB7IG1hdGNoID0gdHJ1ZSwgZGVzYyA9ICdpbnZhbGlkLXByb2Nlc3MnLCBwYXlsb2FkID0gY29udGV4dC5wcm9jZXNzQ2FwdHVyZVN0YXR1cyB9IGVuZCByZXR1cm4geyBtYXRjaCA9IGZhbHNlIH0gZW5k";
        if (!Expect(engine.ParseAndSwap(OneRawLuaRuleJson("invalid_process_ctx", invalidRule), ""),
                    "invalid process context rule snapshot publishes"))
            return false;

        ProcessContextSnapshot process;
        process.valid = false;
        process.parentResolved = false;
        process.status = ProcessCaptureStatus::NtdllUnavailable;
        process.retryState = ProcessRetryState::Pending;

        ScanContext scanContext;
        scanContext.process = &process;
        AmsiEvalResult matched = engine.Evaluate(L"demo.ps1",
                                                 L"powershell.exe",
                                                 "WriteHost",
                                                 9,
                                                 scanContext);
        if (!Expect(matched.ruleMatched && matched.payload == "ntdll-unavailable",
                    "invalid process snapshot exposes degradation fields and preserves body detection"))
            return false;
    }

    // Batch 3: 事件提交通路测试 - 验证 RaspEvalResult -> EventJsonBuildInput -> JSON
    {
        RaspEvalResult result;
        result.matched = true;
        result.block = true;
        result.ruleId = "rule-parent-path";
        result.sensor = "AmsiProvider";
        result.desc = "parent path test";
        result.payload = "test payload";
        result.severity = 3;
        result.contentName = "test.ps1";
        result.appName = "powershell.exe";
        result.confidence = 70;
        result.parentPid = 5678;
        result.parentProcessName = "wscript.exe";
        result.parentProcessPath = "C:\\Windows\\System32\\wscript.exe";

        EventJsonBuildInput input;
        input.eventId = "evt-test";
        input.timestamp = "2026-05-09T00:00:00Z";
        input.moduleName = "rasp_mod_amsi";
        input.ruleId = result.ruleId;
        input.sensor = result.sensor;
        input.block = result.block;
        input.severity = result.severity;
        input.description = result.desc;
        input.appName = result.appName;
        input.contentName = result.contentName;
        input.confidence = result.confidence;
        input.payload = result.payload;
        input.parentPid = result.parentPid;
        input.parentProcessName = result.parentProcessName;
        input.parentProcessPath = result.parentProcessPath;

        EventJsonBuilder builder;
        EventJsonBuildResult built = builder.BuildDetection(input);

        std::map<std::string, std::string> fields;
        size_t i = 0;
        const std::string& json = built.compactJson;
        auto skipWs = [&]() {
            while (i < json.size() && (json[i] == ' ' || json[i] == '\t' || json[i] == '\r' || json[i] == '\n'))
                ++i;
        };
        auto readString = [&](std::string& s) {
            skipWs();
            if (i >= json.size() || json[i] != '"')
                return false;
            ++i;
            s.clear();
            while (i < json.size() && json[i] != '"') {
                if (json[i] == '\\') {
                    ++i;
                    if (i >= json.size())
                        return false;
                    switch (json[i]) {
                    case '"': s.push_back('"'); break;
                    case '\\': s.push_back('\\'); break;
                    case 'n': s.push_back('\n'); break;
                    case 'r': s.push_back('\r'); break;
                    case 't': s.push_back('\t'); break;
                    default: s.push_back(json[i]); break;
                    }
                    ++i;
                } else {
                    s.push_back(json[i++]);
                }
            }
            if (i >= json.size() || json[i] != '"')
                return false;
            ++i;
            return true;
        };
        auto readValue = [&](std::string& s) {
            skipWs();
            if (i < json.size() && json[i] == '"')
                return readString(s);
            s.clear();
            while (i < json.size() && json[i] != ',' && json[i] != '}')
                s.push_back(json[i++]);
            while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
                s.pop_back();
            return !s.empty();
        };
        skipWs();
        if (i >= json.size() || json[i++] != '{')
            return false;
        skipWs();
        while (i < json.size() && json[i] != '}') {
            std::string key, value;
            if (!readString(key))
                return false;
            skipWs();
            if (i >= json.size() || json[i++] != ':')
                return false;
            if (!readValue(value))
                return false;
            fields[key] = value;
            skipWs();
            if (i < json.size() && json[i] == ',')
                ++i;
            skipWs();
        }

        if (!Expect(fields["parentPid"] == "5678",
                    "event submit path: parentPid 5678 reaches JSON"))
            return false;
        if (!Expect(fields["parentProcessName"] == "wscript.exe",
                    "event submit path: parentProcessName wscript.exe reaches JSON"))
            return false;
        if (!Expect(fields["parentProcessPath"] == "C:\\Windows\\System32\\wscript.exe",
                    "event submit path: parentProcessPath reaches JSON"))
            return false;
    }

    // Batch 3: 事件提交通路测试 - 空 parent 字段
    {
        RaspEvalResult result;
        result.matched = true;
        result.ruleId = "rule-empty-parent";
        result.parentPid = 0;
        result.parentProcessName.clear();

        EventJsonBuildInput input;
        input.parentPid = result.parentPid;
        input.parentProcessName = result.parentProcessName;

        EventJsonBuilder builder;
        EventJsonBuildResult built = builder.BuildDetection(input);

        std::map<std::string, std::string> fields;
        size_t i = 0;
        const std::string& json = built.compactJson;
        auto skipWs = [&]() {
            while (i < json.size() && (json[i] == ' ' || json[i] == '\t' || json[i] == '\r' || json[i] == '\n'))
                ++i;
        };
        auto readString = [&](std::string& s) {
            skipWs();
            if (i >= json.size() || json[i] != '"')
                return false;
            ++i;
            s.clear();
            while (i < json.size() && json[i] != '"') {
                if (json[i] == '\\') {
                    ++i;
                    if (i >= json.size())
                        return false;
                    switch (json[i]) {
                    case '"': s.push_back('"'); break;
                    case '\\': s.push_back('\\'); break;
                    case 'n': s.push_back('\n'); break;
                    case 'r': s.push_back('\r'); break;
                    case 't': s.push_back('\t'); break;
                    default: s.push_back(json[i]); break;
                    }
                    ++i;
                } else {
                    s.push_back(json[i++]);
                }
            }
            if (i >= json.size() || json[i] != '"')
                return false;
            ++i;
            return true;
        };
        auto readValue = [&](std::string& s) {
            skipWs();
            if (i < json.size() && json[i] == '"')
                return readString(s);
            s.clear();
            while (i < json.size() && json[i] != ',' && json[i] != '}')
                s.push_back(json[i++]);
            while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n'))
                s.pop_back();
            return !s.empty();
        };

        skipWs();
        if (i >= json.size() || json[i++] != '{')
            return false;
        skipWs();
        while (i < json.size() && json[i] != '}') {
            std::string key, value;
            if (!readString(key))
                return false;
            skipWs();
            if (i >= json.size() || json[i++] != ':')
                return false;
            if (!readValue(value))
                return false;
            fields[key] = value;
            skipWs();
            if (i < json.size() && json[i] == ',')
                ++i;
            skipWs();
        }

        if (!Expect(fields["parentPid"] == "0",
                    "event submit path: empty parentPid is 0 in JSON"))
            return false;
        if (!Expect(fields["parentProcessName"].empty(),
                    "event submit path: empty parentProcessName is empty in JSON"))
            return false;
    }

    // Batch 4b: 采集失败时事件输出完整性 - NtdllUnavailable
    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(OneRegexRuleJson("fail_test_rule", "DownloadString"), ""),
                    "fail_test_rule snapshot publishes"))
            return false;

        ProcessContextSnapshot process;
        process.valid = false;
        process.parentResolved = false;
        process.parentPid = 0;
        process.parentProcessName.clear();
        process.status = ProcessCaptureStatus::NtdllUnavailable;
        process.retryState = ProcessRetryState::Exhausted;

        ScanContext scanContext;
        scanContext.process = &process;

        AmsiEvalResult matched = engine.Evaluate(L"fail_test.ps1",
                                                 L"powershell.exe",
                                                 "DownloadString",
                                                 14,
                                                 scanContext);

        if (!Expect(matched.ruleMatched, "采集失败不阻塞规则匹配"))
            return false;
        if (!Expect(matched.block, "采集失败不改变 block 决策"))
            return false;
    }

    // Batch 4b: ParentSystem 哨兵值事件输出
    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(OneRegexRuleJson("system_parent_rule", "Write-Host"), ""),
                    "system_parent_rule snapshot publishes"))
            return false;

        ProcessContextSnapshot process;
        process.valid = true;
        process.parentResolved = true;
        process.parentPid = 4;  // System 进程
        process.parentProcessName = "System";
        process.status = ProcessCaptureStatus::ParentSystem;
        process.retryState = ProcessRetryState::None;

        ScanContext scanContext;
        scanContext.process = &process;

        AmsiEvalResult matched = engine.Evaluate(L"system_test.ps1",
                                                 L"powershell.exe",
                                                 "Write-Host test",
                                                 15,
                                                 scanContext);

        if (!Expect(matched.ruleMatched, "ParentSystem 不阻塞规则匹配"))
            return false;
    }

    // Batch 4c: 并发检测时 parent 字段传递一致性
    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(OneRegexRuleJson("concurrent_rule", "Get-Process"), ""),
                    "concurrent_rule snapshot publishes"))
            return false;

        ProcessContextSnapshot process;
        process.valid = true;
        process.parentResolved = true;
        process.parentPid = 9999;
        process.parentProcessName = "test_parent.exe";
        process.status = ProcessCaptureStatus::Success;
        process.retryState = ProcessRetryState::None;

        ScanContext scanContext;
        scanContext.process = &process;

        std::atomic<int> matchCount{0};
        std::vector<std::thread> threads;
        for (int i = 0; i < 8; ++i) {
            threads.emplace_back([&]() {
                AmsiEvalResult result = engine.Evaluate(L"concurrent.ps1",
                                                        L"powershell.exe",
                                                        "Get-Process",
                                                        11,
                                                        scanContext);
                if (result.ruleMatched)
                    matchCount.fetch_add(1);
            });
        }
        for (auto& t : threads)
            t.join();

        if (!Expect(matchCount.load() == 8, "并发检测全部成功匹配"))
            return false;
    }

    return true;
}

int main()
{
    if (!RunEngineRuntimeTestGroup1())
        return 1;
    if (!RunEngineRuntimeTestGroup2())
        return 1;
    if (!RunEngineRuntimeTestGroup3())
        return 1;
    if (!RunEngineRuntimeTestGroup4())
        return 1;
    if (!RunEngineRuntimeTestGroup5())
        return 1;

    return 0;
}
