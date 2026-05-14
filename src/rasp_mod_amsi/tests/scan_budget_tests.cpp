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
