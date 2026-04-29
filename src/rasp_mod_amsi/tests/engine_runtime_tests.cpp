#include "../include/engine_runtime.h"
#include "../include/amsi_rule_engine.h"

#include <atomic>
#include <chrono>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

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

std::unique_ptr<EngineRuntime> MakeRuntime()
{
    return std::make_unique<EngineRuntime>(
        []() { return std::make_unique<AmsiRuleEngine>(); },
        [](AmsiRuleEngine&) { return true; });
}

class TestAmsiRuleEngine : public AmsiRuleEngine
{
public:
    using AmsiRuleEngine::BuildNextSnapshot;
    using AmsiRuleEngine::ParseAndSwap;
};

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

} // namespace

int main()
{
    {
        auto runtime = MakeRuntime();
        if (!Expect(runtime->GetState() == EngineState::Uninitialized,
                    "new runtime starts uninitialized"))
            return 1;
        if (!Expect(runtime->EnsureInitialized(), "runtime initializes"))
            return 1;
        if (!Expect(runtime->GetState() == EngineState::Ready,
                    "runtime becomes ready after initialization"))
            return 1;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        {
            auto guard = runtime->TryEnterScan();
            if (!Expect(guard.IsActive(), "scan can enter ready runtime"))
                return 1;
            if (!Expect(runtime->ActiveScanCount() == 1,
                        "scan guard increments active count"))
                return 1;
        }
        if (!Expect(runtime->ActiveScanCount() == 0,
                    "scan guard destructor decrements active count"))
            return 1;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        auto guard = runtime->TryEnterScan();
        auto start = std::chrono::steady_clock::now();
        bool drained = runtime->BeginShutdown("test_shutdown", 25);
        auto elapsed = std::chrono::steady_clock::now() - start;
        if (!Expect(!drained, "shutdown times out while scan is active"))
            return 1;
        if (!Expect(elapsed < std::chrono::milliseconds(500),
                    "shutdown drain is bounded"))
            return 1;
        if (!Expect(runtime->GetState() == EngineState::Inert,
                    "shutdown timeout enters inert"))
            return 1;
        auto rejected = runtime->TryEnterScan();
        if (!Expect(!rejected.IsActive(), "inert runtime rejects new scans"))
            return 1;
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
            return 1;
        if (!Expect(runtime->ActiveScanCount() == 0,
                    "concurrent scan guard releases active count"))
            return 1;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        if (!Expect(runtime->CanAttemptReload(),
                    "ready runtime can attempt reload"))
            return 1;
        auto reload = runtime->TryEnterReload("test_reload");
        if (!Expect(reload.IsActive(), "ready runtime enters reload"))
            return 1;
        if (!Expect(runtime->GetState() == EngineState::Reloading,
                    "reload guard sets reloading state"))
            return 1;
        auto repeated = runtime->TryEnterReload("repeat_reload");
        if (!Expect(!repeated.IsActive(), "reloading rejects repeated reload"))
            return 1;
        auto scan = runtime->TryEnterScan();
        if (!Expect(scan.IsActive(), "reloading allows scan on current snapshot"))
            return 1;
        reload.Complete(true, "published");
        if (!Expect(runtime->GetState() == EngineState::Ready,
                    "successful reload returns ready"))
            return 1;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        {
            auto reload = runtime->TryEnterReload("implicit_failure");
            if (!Expect(reload.IsActive(), "reload guard enters before destructor test"))
                return 1;
        }
        if (!Expect(runtime->GetState() == EngineState::Ready,
                    "reload guard destructor restores ready on implicit failure"))
            return 1;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        auto reload = runtime->TryEnterReload("shutdown_priority");
        if (!Expect(reload.IsActive(), "reload enters before shutdown priority test"))
            return 1;
        bool drained = runtime->BeginShutdown("shutdown_during_reload", 25);
        if (!Expect(drained, "shutdown drains when no scans are active"))
            return 1;
        if (!Expect(runtime->GetState() == EngineState::Inert,
                    "shutdown during reload enters inert"))
            return 1;
        reload.Complete(true, "late_success");
        if (!Expect(runtime->GetState() == EngineState::Inert,
                    "late reload completion does not restore ready"))
            return 1;
        auto rejectedScan = runtime->TryEnterScan();
        if (!Expect(!rejectedScan.IsActive(), "inert rejects scan after reload shutdown race"))
            return 1;
        auto rejectedReload = runtime->TryEnterReload("after_shutdown");
        if (!Expect(!rejectedReload.IsActive(), "inert rejects reload after shutdown"))
            return 1;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        runtime->EnterFaulted("test_fault");
        auto scan = runtime->TryEnterScan();
        if (!Expect(!scan.IsActive(), "faulted rejects scan"))
            return 1;
        auto reload = runtime->TryEnterReload("faulted_reload");
        if (!Expect(!reload.IsActive(), "faulted rejects reload"))
            return 1;
    }

    {
        auto runtime = MakeRuntime();
        runtime->EnsureInitialized();
        bool drained = runtime->BeginShutdown("publish_before_reload", 25);
        if (!Expect(drained, "shutdown before publish drains"))
            return 1;
        auto reload = runtime->TryEnterReload("publish_after_shutdown");
        if (!Expect(!reload.IsActive(),
                    "reload build success but publish after shutdown is rejected"))
            return 1;
        if (!Expect(runtime->GetState() == EngineState::Inert,
                    "publish after shutdown rejection does not restore ready"))
            return 1;
    }

    {
        TestAmsiRuleEngine engine;
        const char* oldScript = "function rule(sensor, context) return { match = true, desc = 'old' } end";
        const char* newScript = "function rule(sensor, context) return { match = true, desc = 'new' } end";
        if (!Expect(engine.ParseAndSwap(OneLuaRuleJson("old_rule", "old_desc", oldScript), ""),
                    "old snapshot publishes"))
            return 1;

        RaspLuaContext ctx;
        auto before = engine.Evaluate("AmsiProvider", ctx);
        if (!Expect(!before.empty() && before[0].ruleId == "old_rule",
                    "old Lua rule matches before reload build"))
            return 1;

        std::string effectiveLib;
        auto next = engine.BuildNextSnapshot(OneLuaRuleJson("new_rule", "new_desc", newScript),
                                             "",
                                             effectiveLib);
        if (!Expect(next != nullptr, "next snapshot builds without publishing"))
            return 1;

        auto duringBuild = engine.Evaluate("AmsiProvider", ctx);
        if (!Expect(!duringBuild.empty() && duringBuild[0].ruleId == "old_rule",
                    "building next snapshot does not clear old snapshot Lua engine"))
            return 1;
    }

    {
        TestAmsiRuleEngine engine;
        if (!Expect(engine.ParseAndSwap(OneRegexRuleJson("split_iex", "IEX"), ""),
                    "split regex snapshot publishes"))
            return 1;

        AmsiEvalResult first = engine.Evaluate(L"same-content", L"powershell.exe", "I", 1);
        if (!Expect(!first.ruleMatched, "first split chunk alone does not match"))
            return 1;

        AmsiEvalResult second = engine.Evaluate(L"same-content", L"powershell.exe", "EX", 2);
        if (!Expect(second.ruleMatched && second.ruleId == "split_iex",
                    "session context exposes split token across chunks"))
            return 1;
    }

    return 0;
}
