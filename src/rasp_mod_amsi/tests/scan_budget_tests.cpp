#include "rasp_lua_engine.h"
#include "rasp_scan_budget.h"

#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

extern "C" {
#include "lua.h"
#include "lauxlib.h"
}

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

std::string g_capturedLog;
RaspDiagSeverity g_capturedSeverity = RaspDiagSeverity::Info;

void CaptureLog(const char* msg)
{
    if (msg)
        g_capturedLog += msg;
}

void CaptureLeveledLog(RaspDiagSeverity severity, const char* msg)
{
    g_capturedSeverity = severity;
    CaptureLog(msg);
}

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
        if (!Expect(exec.regexLimitType == "max_regex_calls", "regex call limit type is recorded"))
            return 1;
        if (!Expect(exec.timedOut, "regex call budget exhaustion stops scan"))
            return 1;
        if (!Expect(exec.timeoutReason == "max_regex_calls_exhausted", "regex call budget reason is recorded"))
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
        g_capturedLog.clear();
        g_capturedSeverity = RaspDiagSeverity::Info;
        engine.SetLogFn(CaptureLog);
        engine.SetLeveledLogFn(CaptureLeveledLog);
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
        if (!Expect(exec.regexRuleLimitHit, "PCRE2 resource limit is recorded as a rule-local limit"))
            return 1;
        if (!Expect(exec.currentRuleLimited, "PCRE2 resource limit marks current rule limited"))
            return 1;
        if (!Expect(!exec.timedOut, "PCRE2 resource limit does not stop the whole scan"))
            return 1;
        if (!Expect(g_capturedLog.find("regex_pattern_limit") != std::string::npos, "PCRE2 regex limit is logged"))
            return 1;
        if (!Expect(g_capturedLog.find("patternIndex=0") != std::string::npos,
                    "PCRE2 regex limit log records the pattern index"))
            return 1;
        if (!Expect(g_capturedLog.find("^(a+)+$") == std::string::npos,
                    "PCRE2 regex limit log does not include the concrete pattern"))
            return 1;
        if (!Expect(g_capturedSeverity == RaspDiagSeverity::Warning, "PCRE2 regex limit is logged as warning"))
            return 1;
    }

    {
        RaspLuaEngine engine;
        g_capturedLog.clear();
        g_capturedSeverity = RaspDiagSeverity::Info;
        engine.SetLogFn(CaptureLog);
        engine.SetLeveledLogFn(CaptureLeveledLog);
        ScanExecutionContext exec;
        exec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec.budget.totalBudgetMs));

        std::string subject = "REGEX_TIMEOUT_PROBE:" + std::string(4096, 'a') + "b";
        std::string matched;
        bool ok = engine.MatchesAnyRegex({"(?s)REGEX_TIMEOUT_PROBE:(?:a|aa)+$"}, subject, matched, &exec);
        if (!Expect(!ok, "JIT stack limited regex probe does not match"))
            return 1;
        if (!Expect(exec.regexLimitHit, "JIT stack limit is treated as a regex limit"))
            return 1;
        if (!Expect(exec.regexRuleLimitHit, "JIT stack limit is treated as a rule-local regex limit"))
            return 1;
        if (!Expect(exec.currentRuleLimited, "JIT stack limit marks current rule limited"))
            return 1;
        if (!Expect(!exec.timedOut, "JIT stack limit does not mark scan execution context timed out"))
            return 1;
        if (!Expect(exec.timeoutReason.empty(), "JIT stack limit does not record a global timeout reason"))
            return 1;
        if (!Expect(exec.regexLimitType == "jit_stack_limit" || exec.regexLimitType == "match_limit" ||
                    exec.regexLimitType == "depth_limit" || exec.regexLimitType == "heap_limit",
                    "regex limit type records the concrete PCRE2 resource limit"))
            return 1;
        if (!Expect(g_capturedLog.find("jit_stack_limit") != std::string::npos ||
                    g_capturedLog.find("match_limit") != std::string::npos ||
                    g_capturedLog.find("depth_limit") != std::string::npos ||
                    g_capturedLog.find("heap_limit") != std::string::npos,
                    "PCRE2 resource limit is logged with a concrete type"))
            return 1;
        if (!Expect(g_capturedSeverity == RaspDiagSeverity::Warning, "PCRE2 resource limit is logged as warning"))
            return 1;
    }

    {
        RaspLuaEngine engine;
        engine.SetLogFn(SilentLog);
        ScanExecutionContext exec;
        exec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec.budget.totalBudgetMs));

        std::string subject = "REGEX_TIMEOUT_PROBE:" + std::string(4096, 'a') + "b SECOND_OK";
        std::string matched;
        bool ok = engine.MatchesAnyRegex({"(?s)REGEX_TIMEOUT_PROBE:(?:a|aa)+$", "SECOND_OK"},
                                         subject,
                                         matched,
                                         &exec);
        if (!Expect(!ok, "regex pattern list stops after a resource-limited pattern"))
            return 1;
        if (!Expect(matched.empty(), "later regex patterns are not evaluated after current rule is limited"))
            return 1;
        if (!Expect(exec.currentRuleLimited && exec.currentRegexPatternIndex == 0,
                    "resource-limited pattern records the failing pattern index"))
            return 1;
    }
    {
        RaspLuaEngine engine;
        engine.SetLogFn(SilentLog);
        if (!Expect(engine.RegexCacheSizeForTesting() == 0, "new engine starts with empty regex cache"))
            return 1;

        ScanExecutionContext exec;
        exec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec.budget.totalBudgetMs));
        std::string matched;
        bool ok = engine.MatchesAnyRegex({"IEX"}, "Invoke IEX test", matched, &exec);
        if (!Expect(ok && matched == "IEX", "C++ regex path compiles and matches first pattern"))
            return 1;
        if (!Expect(engine.RegexCacheSizeForTesting() == 1, "first pattern is cached"))
            return 1;

        ScanExecutionContext exec2;
        exec2.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec2.budget.totalBudgetMs));
        matched.clear();
        ok = engine.MatchesAnyRegex({"IEX"}, "Invoke IEX again", matched, &exec2);
        if (!Expect(ok && matched == "IEX", "cached C++ regex pattern still matches"))
            return 1;
        if (!Expect(engine.RegexCacheSizeForTesting() == 1, "reusing same C++ pattern does not grow cache"))
            return 1;

        ScanExecutionContext exec3;
        exec3.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec3.budget.totalBudgetMs));
        matched.clear();
        g_capturedLog.clear();
        engine.SetLogFn(CaptureLog);
        ok = engine.MatchesAnyRegex({"("}, "invalid", matched, &exec3);
        if (!Expect(!ok, "invalid C++ regex pattern is skipped"))
            return 1;
        if (!Expect(g_capturedLog.find("pattern=") == std::string::npos,
                    "invalid C++ regex compile log does not include the concrete pattern"))
            return 1;
        if (!Expect(engine.RegexCacheSizeForTesting() == 1, "invalid C++ pattern is not cached"))
            return 1;

        ScanExecutionContext exec4;
        exec4.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec4.budget.totalBudgetMs));
        matched.clear();
        ok = engine.MatchesAnyRegex({"AMSI"}, "AMSI context", matched, &exec4);
        if (!Expect(ok && matched == "AMSI", "different C++ regex pattern matches"))
            return 1;
        if (!Expect(engine.RegexCacheSizeForTesting() == 2, "different C++ pattern gets its own cache entry"))
            return 1;

        RaspLuaEngine otherEngine;
        otherEngine.SetLogFn(SilentLog);
        if (!Expect(otherEngine.RegexCacheSizeForTesting() == 0, "separate engine has independent regex cache"))
            return 1;
    }
    {
        RaspLuaEngine engine;
        g_capturedLog.clear();
        g_capturedSeverity = RaspDiagSeverity::Info;
        engine.SetLogFn(CaptureLog);
        engine.SetLeveledLogFn(CaptureLeveledLog);

        ScanExecutionContext exec;
        exec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec.budget.totalBudgetMs));
        std::string subject;
        subject.push_back('A');
        subject.push_back(static_cast<char>(0xC0));
        subject.push_back(static_cast<char>(0xAF));
        subject.append(" test amsiutilszxc");

        std::string matched;
        bool ok = engine.MatchesAnyRegex({"amsiutilszxc", "test", "A"}, subject, matched, &exec);
        if (!Expect(!ok, "invalid UTF-8 regex subject does not match"))
            return 1;
        if (!Expect(exec.regexInvalidUtf8Subject, "invalid UTF-8 subject is recorded in execution context"))
            return 1;
        if (!Expect(exec.regexInvalidUtf8Hits == 1, "invalid UTF-8 subject is recorded once"))
            return 1;
        if (!Expect(exec.regexCalls == 1, "invalid UTF-8 subject stops after the first PCRE2 call"))
            return 1;
        if (!Expect(g_capturedLog.find("utf8_invalid_subject") != std::string::npos,
                    "invalid UTF-8 subject is logged with a clear error name"))
            return 1;
        if (!Expect(g_capturedLog.find("patternIndex=0") != std::string::npos,
                    "invalid UTF-8 subject log records the first failing pattern index"))
            return 1;

        g_capturedLog.clear();
        ok = engine.MatchesAnyRegex({"amsiutilszxc"}, subject, matched, &exec);
        if (!Expect(!ok, "execution context suppresses later invalid UTF-8 regex attempts"))
            return 1;
        if (!Expect(g_capturedLog.empty(), "later invalid UTF-8 attempts do not repeat logs"))
            return 1;
    }
    {
        RaspLuaEngine engine;
        engine.SetLogFn(SilentLog);

        ScanExecutionContext exec;
        exec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec.budget.totalBudgetMs));
        std::string matched;
        bool ok = engine.MatchesAnyRegex({"downloadstring"}, "AMSI context only", matched, &exec);
        if (!Expect(!ok, "literal-prefix fast reject skips impossible fixed-first-char pattern"))
            return 1;
        if (!Expect(exec.regexCalls == 0, "fast rejected pattern does not consume regexCalls budget"))
            return 1;
        if (!Expect(exec.regexPrefixSkips == 1, "fast rejected pattern increments regexPrefixSkips"))
            return 1;

        ScanExecutionContext minExec;
        minExec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(minExec.budget.totalBudgetMs));
        matched.clear();
        ok = engine.MatchesAnyRegex({"downloadstring"}, "down", matched, &minExec);
        if (!Expect(!ok, "minLength fast reject skips subject shorter than possible match"))
            return 1;
        if (!Expect(minExec.regexCalls == 0, "minLength fast reject does not consume regexCalls budget"))
            return 1;
        if (!Expect(minExec.regexPrefixSkips == 1, "minLength fast reject increments regexPrefixSkips"))
            return 1;

        ScanExecutionContext matchExec;
        matchExec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(matchExec.budget.totalBudgetMs));
        matched.clear();
        ok = engine.MatchesAnyRegex({"downloadstring"}, "Invoke downloadstring now", matched, &matchExec);
        if (!Expect(ok && matched == "downloadstring", "possible fixed-first-char pattern still reaches pcre2_match"))
            return 1;
        if (!Expect(matchExec.regexCalls == 1, "matching pattern consumes exactly one regexCalls budget"))
            return 1;
        if (!Expect(matchExec.regexPrefixSkips == 0, "matching pattern is not counted as prefix skipped"))
            return 1;

        ScanExecutionContext bitmapExec;
        bitmapExec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(bitmapExec.budget.totalBudgetMs));
        matched.clear();
        ok = engine.MatchesAnyRegex({"(?i)amsiutils"}, "ZZZ no useful first byte", matched, &bitmapExec);
        if (!Expect(!ok, "case-insensitive first bitmap rejects subject with no possible first byte"))
            return 1;
        if (!Expect(bitmapExec.regexCalls == 0, "bitmap fast reject does not consume regexCalls budget"))
            return 1;
        if (!Expect(bitmapExec.regexPrefixSkips == 1, "bitmap fast reject increments regexPrefixSkips"))
            return 1;

        ScanExecutionContext anyExec;
        anyExec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(anyExec.budget.totalBudgetMs));
        matched.clear();
        ok = engine.MatchesAnyRegex({".{0,16}IEX"}, "AAAA", matched, &anyExec);
        if (!Expect(!ok, "pattern without a fixed first byte still evaluates normally"))
            return 1;
        if (!Expect(anyExec.regexCalls == 1, "non-prefix-constrained pattern consumes regexCalls budget"))
            return 1;
        if (!Expect(anyExec.regexPrefixSkips == 0, "non-prefix-constrained pattern is not prefix skipped"))
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

    {
        RaspLuaEngine engine;
        engine.SetLogFn(SilentLog);
        const char* source = "function rule(sensor, context) return { match = true, desc = 'source-ok' } end";
        engine.Precompile("explicit_source", source, false);

        ScanExecutionContext exec;
        exec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec.budget.totalBudgetMs));
        RaspLuaResult result = engine.Run("explicit_source", "AmsiProvider", RaspLuaContext{}, 500000, {}, &exec);
        if (!Expect(result.matched && result.desc == "source-ok", "explicit source Precompile still runs"))
            return 1;
    }

    {
        RaspLuaEngine engine;
        engine.SetLogFn(SilentLog);
        const char* source = "function rule(sensor, context) return { match = true, desc = 'not-bytecode' } end";
        engine.Precompile("invalid_bytecode", source, true);
        if (!Expect(!engine.IsLoaded("invalid_bytecode"), "invalid bytecode payload is not cached"))
            return 1;
    }

    {
        RaspLuaEngine engine;
        engine.SetLogFn(SilentLog);
        std::string bytecode = CompileLuaBytecode(
            "function rule(sensor, context) return { match = true, desc = 'bytecode-ok', payload = context.body } end",
            "=bytecode_ok");
        if (!Expect(!bytecode.empty(), "test fixture compiles Lua bytecode"))
            return 1;

        engine.Precompile("bytecode_ok", bytecode, true);
        if (!Expect(engine.IsLoaded("bytecode_ok"), "valid bytecode payload is cached"))
            return 1;

        RaspLuaContext ctx;
        ctx.fields.push_back({"body", "payload-from-bytecode", true});
        ScanExecutionContext exec;
        exec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec.budget.totalBudgetMs));
        RaspLuaResult result = engine.Run("bytecode_ok", "AmsiProvider", ctx, 500000, {}, &exec);
        if (!Expect(result.matched && result.desc == "bytecode-ok" && result.payload == "payload-from-bytecode",
                    "valid bytecode runs and receives context"))
            return 1;
    }

    {
        RaspLuaEngine engine;
        engine.SetLogFn(SilentLog);
        std::string bytecode = CompileLuaBytecode(
            "function rule(sensor, context) while true do end end",
            "=bytecode_timeout");
        if (!Expect(!bytecode.empty(), "test fixture compiles timeout bytecode"))
            return 1;

        engine.Precompile("bytecode_timeout", bytecode, true);
        ScanExecutionContext exec;
        exec.budget.luaBudgetMs = 1000;
        exec.budget.maxLuaInstructionCount = 1000;
        exec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec.budget.totalBudgetMs));
        RaspLuaResult result = engine.Run("bytecode_timeout", "AmsiProvider", RaspLuaContext{}, 500000, {}, &exec);
        if (!Expect(!result.matched, "timed out bytecode script does not match"))
            return 1;
        if (!Expect(result.timedOut && exec.timedOut && exec.timeoutReason == "lua_timeout",
                    "bytecode path remains governed by Lua budget hook"))
            return 1;
    }

    return 0;
}
