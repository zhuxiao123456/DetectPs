#include "rasp_lua_engine.h"
#include "rasp_scan_budget.h"

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

void SilentLog(const char*)
{
}

} // namespace

int main()
{
    {
        ScanDeadline deadline = ScanDeadline::FromNow(std::chrono::milliseconds(1));
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        if (!Expect(deadline.Expired(), "steady deadline expires"))
            return 1;
    }

    {
        RaspLuaEngine engine;
        engine.SetLogFn(SilentLog);
        engine.Precompile("lua_timeout", "function rule(sensor, context) while true do end end");

        ScanExecutionContext exec;
        exec.budget.totalBudgetMs = 1000;
        exec.budget.luaBudgetMs = 1000;
        exec.budget.maxLuaInstructionCount = 1000;
        exec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec.budget.totalBudgetMs));

        RaspLuaResult result = engine.Run(
            "lua_timeout",
            "AmsiProvider",
            RaspLuaContext{},
            500000,
            {},
            &exec);

        if (!Expect(!result.matched, "timed out Lua script does not match"))
            return 1;
        if (!Expect(result.timedOut, "Lua timeout is surfaced in result"))
            return 1;
        if (!Expect(exec.timedOut, "Lua timeout marks scan execution context"))
            return 1;
        if (!Expect(exec.timeoutReason == "lua_timeout", "Lua timeout reason is recorded"))
            return 1;

        exec = ScanExecutionContext{};
        exec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec.budget.totalBudgetMs));
        engine.Precompile("lua_ok", "function rule(sensor, context) return { match = true, desc = 'ok' } end");
        result = engine.Run("lua_ok", "AmsiProvider", RaspLuaContext{}, 500000, {}, &exec);
        if (!Expect(result.matched, "Lua state remains usable after timeout"))
            return 1;
    }

#ifdef RASP_PCRE2_AVAILABLE
    {
        RaspLuaEngine engine;
        engine.SetLogFn(SilentLog);
        ScanExecutionContext exec;
        exec.budget.maxRegexCalls = 0;
        exec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec.budget.totalBudgetMs));
        std::string matched;
        bool ok = engine.MatchesAnyRegex({"abc"}, "abc", matched, &exec);
        if (!Expect(!ok, "regex call limit prevents matching"))
            return 1;
        if (!Expect(exec.regexLimitHit, "regex call limit is recorded"))
            return 1;
        if (!Expect(exec.regexLimitType == "call_limit", "regex call limit type is recorded"))
            return 1;
    }

    {
        RaspLuaEngine engine;
        engine.SetLogFn(SilentLog);
        ScanExecutionContext exec;
        exec.budget.maxRegexSubjectBytes = 1024;
        exec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec.budget.totalBudgetMs));

        std::string subject(70 * 1024, 'A');
        subject.push_back('Z');
        std::string matched;
        bool ok = engine.MatchesAnyRegex({"Z$"}, subject, matched, &exec);
        if (!Expect(!ok, "truncated regex subject does not match suffix outside budget"))
            return 1;
        if (!Expect(exec.regexSubjectTruncated, "regex subject truncation is recorded"))
            return 1;
    }

    {
        RaspLuaEngine engine;
        engine.SetLogFn(SilentLog);
        ScanExecutionContext exec;
        exec.budget.pcre2MatchLimit = 1;
        exec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec.budget.totalBudgetMs));

        std::string subject(4096, 'a');
        subject.push_back('b');
        std::string matched;
        bool ok = engine.MatchesAnyRegex({"^(a+)+$"}, subject, matched, &exec);
        if (!Expect(!ok, "catastrophic regex does not match under tiny match limit"))
            return 1;
        if (!Expect(exec.regexLimitHit, "PCRE2 match/depth/heap limit hit is recorded"))
            return 1;
    }
#endif

    {
        ScanExecutionContext exec;
        exec.budget.maxRules = 1;
        if (!Expect(exec.TryEnterRule(), "first rule enters under maxRules"))
            return 1;
        if (!Expect(!exec.TryEnterRule(), "maxRules stops further rule evaluation"))
            return 1;
        if (!Expect(exec.timedOut, "maxRules exhaustion marks execution context"))
            return 1;
        if (!Expect(exec.timeoutReason == "rule_budget_exceeded", "maxRules reason is recorded"))
            return 1;
    }

    return 0;
}
