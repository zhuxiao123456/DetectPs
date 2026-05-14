// =========================================================================
// rasp_lua_engine.cpp — Shared Lua 5.4 sandbox (rasp_rule_engine library).
//
// Original implementation: rasp_mod_iis7/src/rasp_lua_engine.cpp, which
// was itself adapted from rasp_mod_amsi/src/amsi_rule_engine.cpp
// (RunLuaScript lines 618-738).
//
// 管理 Lua 5.4 虚拟机的生命周期，提供极其严格的隔离环境（Sandbox），
// 将 C++ 侧的上下文数据（如 HTTP 请求、脚本内容）注入 Lua，执行动态安全规则，并安全地返回判定结果
// =========================================================================

#include "../include/rasp_lua_engine.h"

#ifdef RASP_PCRE2_AVAILABLE
// PCRE2 must be configured before the header is included.
#define PCRE2_CODE_UNIT_WIDTH 8
#include "pcre2.h"
#endif

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstring>

namespace {

constexpr uint32_t kLuaHookInstructionStep = 1000;
constexpr const char* kLuaBudgetRegistryKey = "rasp_scan_budget";

bool IsLua54BytecodePayload(const std::string& payload)
{
    static const unsigned char kLua54Magic[] = {0x1b, 'L', 'u', 'a', 0x54};
    return payload.size() >= sizeof(kLua54Magic) &&
           std::memcmp(payload.data(), kLua54Magic, sizeof(kLua54Magic)) == 0;
}

struct LuaBytecodeReader
{
    const char* data = nullptr;
    size_t size = 0;
    bool consumed = false;
};

const char* ReadLuaBytecode(lua_State*, void* userData, size_t* size)
{
    auto* reader = static_cast<LuaBytecodeReader*>(userData);
    if (!reader || reader->consumed) {
        *size = 0;
        return nullptr;
    }

    reader->consumed = true;
    *size = reader->size;
    return reader->data;
}

} // namespace

// ── Destructor ────────────────────────────────────────────────────────────────
// 释放 PCRE2 预编译的正则表达式对象。使用了 std::lock_guard 保证线程安全释放。
RaspLuaEngine::~RaspLuaEngine()
{
#ifdef RASP_PCRE2_AVAILABLE
    std::lock_guard<std::mutex> lk(m_regexMutex);
    for (auto &kv : m_regexCache)
        pcre2_code_free(kv.second);
    m_regexCache.clear();
#endif
}

// ── Log routing ───────────────────────────────────────────────────────────────

void RaspLuaEngine::SetLogFn(RaspLuaLogFn fn)
{
    m_logFn = fn;
}

void RaspLuaEngine::Log(const char *msg) const
{
    if (m_logFn)
        m_logFn(msg);
    else
        OutputDebugStringA(msg); // safe fallback before SetLogFn
}

#ifdef RASP_PCRE2_AVAILABLE

namespace {

pcre2_match_context* CreateBudgetedMatchContext(const ScanExecutionContext* exec)
{
    pcre2_match_context* mctx = pcre2_match_context_create(nullptr);
    if (!mctx)
        return nullptr;

    if (exec) {
        pcre2_set_match_limit(mctx, exec->budget.pcre2MatchLimit);
        pcre2_set_depth_limit(mctx, exec->budget.pcre2DepthLimit);
        pcre2_set_heap_limit(mctx, exec->budget.pcre2HeapLimitKiB);
    } else {
        pcre2_set_match_limit(mctx, 500000);
    }
    return mctx;
}

void RecordRegexLimit(int rc, ScanExecutionContext* exec)
{
    if (!exec)
        return;

    if (rc == PCRE2_ERROR_MATCHLIMIT) {
        exec->regexLimitHit = true;
        exec->regexLimitType = "match_limit";
        exec->MarkTimeout("regex_limit_hit");
    } else if (rc == PCRE2_ERROR_DEPTHLIMIT) {
        exec->regexLimitHit = true;
        exec->regexLimitType = "depth_limit";
        exec->MarkTimeout("regex_limit_hit");
    } else if (rc == PCRE2_ERROR_HEAPLIMIT) {
        exec->regexLimitHit = true;
        exec->regexLimitType = "heap_limit";
        exec->MarkTimeout("regex_limit_hit");
    }
}

} // namespace

/*
 * 首次使用时编译模式；后续调用返回缓存的代码对象。
 * 尝试JIT编译，但如果不可用，则会自动跳过（例如，在不支持PCRE2 JIT的平台/架构上）。
 * 在MatchesAnyRegex和Lua绑定中，每次调用的匹配限制为500000步，这限制了任何病理模式的回溯（正则的ddos攻击）。
 * 流程: 先查锁，如果缓存有直接返回 -> 编译正则 -> 尝试开启 PCRE2_JIT_COMPLETE 硬件级加速 -> 存入缓存 m_regexCache
 * */
pcre2_real_code_8 *RaspLuaEngine::GetOrCompilePcre2(const std::string &pattern) const
{
    {
        std::lock_guard<std::mutex> lk(m_regexMutex);
        auto it = m_regexCache.find(pattern);
        if (it != m_regexCache.end())
            return it->second;
    }

    int errcode = 0;
    PCRE2_SIZE erroffset = 0;
    pcre2_code *re = pcre2_compile(
        reinterpret_cast<PCRE2_SPTR8>(pattern.c_str()),
        PCRE2_ZERO_TERMINATED,
        PCRE2_UTF | PCRE2_UCP,
        &errcode, &erroffset, nullptr);

    if (!re)
    {
        PCRE2_UCHAR8 errbuf[256];
        pcre2_get_error_message(errcode, errbuf, sizeof(errbuf));
        char msg[512];
        snprintf(msg, sizeof(msg),
                 "[RaspLuaEngine] regex compile error at offset %zu: %s  pattern=%s\n",
                 (size_t)erroffset,
                 reinterpret_cast<const char *>(errbuf),
                 pattern.c_str());
        Log(msg);
        return nullptr;
    }

    // Best-effort JIT; continues without JIT if platform doesn't support it.
    pcre2_jit_compile(re, PCRE2_JIT_COMPLETE);

    {
        std::lock_guard<std::mutex> lk(m_regexMutex);
        // Check again under lock — another thread may have compiled while we did.
        auto it = m_regexCache.find(pattern);
        if (it != m_regexCache.end())
        {
            pcre2_code_free(re); // discard our copy
            return it->second;
        }
        m_regexCache.emplace(pattern, re);
    }
    return re;
}

size_t RaspLuaEngine::RegexCacheSizeForTesting() const
{
    std::lock_guard<std::mutex> lk(m_regexMutex);
    return m_regexCache.size();
}

// ── MatchesAnyRegex ───────────────────────────────────────────────────────────

bool RaspLuaEngine::MatchesAnyRegex(const std::vector<std::string> &patterns,
                                     const std::string &text,
                                     std::string &matchedPatternOut,
                                     ScanExecutionContext *exec) const
{
    size_t subjectLen = exec ? exec->BoundedRegexSubjectLength(text.size()) : text.size();
    for (const auto &pat : patterns)
    {
        if (pat.empty())
            continue;

        if (exec && !exec->TryEnterRegexCall())
            return false;

        pcre2_code *re = GetOrCompilePcre2(pat);
        if (!re)
            continue;

        pcre2_match_context *mctx = CreateBudgetedMatchContext(exec);

        pcre2_match_data *md = pcre2_match_data_create_from_pattern(re, nullptr);
        if (!md)
        {
            if (mctx)
                pcre2_match_context_free(mctx);
            continue;
        }

        int rc = pcre2_match(
            re,
            reinterpret_cast<PCRE2_SPTR8>(text.c_str()),
            subjectLen,
            0, // start offset
            0, // options
            md,
            mctx);

        pcre2_match_data_free(md);
        if (mctx)
            pcre2_match_context_free(mctx);

        if (rc >= 0)
        {
            matchedPatternOut = pat;
            return true;
        }
        RecordRegexLimit(rc, exec);
        // PCRE2_ERROR_NOMATCH (-1) is expected; other negative codes are errors.
    }
    return false;
}

// ── Lua C functions: regex_match / regex_capture ──────────────────────────────
/*
 * 功能：注册到 Lua 内部的全局函数（供 Lua 脚本调用）。
 * 流程：通过 LUA_REGISTRYINDEX 获取当前引擎的指针 -> 取出 Lua 栈中的参数（pattern, text）-> 调用 pcre2_match
 * 关键安全设计：强制设置 pcre2_set_match_limit(mctx, 500000) 限制回溯步数 -> 返回结果给 Lua 栈。
 * */
static int lua_pcre2_match(lua_State *L)
{
    // regex_match(pattern, text) → boolean
    const char *pattern = luaL_checkstring(L, 1);
    size_t textLen = 0;
    const char *text = luaL_checklstring(L, 2, &textLen);

    lua_getfield(L, LUA_REGISTRYINDEX, "rasp_engine");
    auto *eng = static_cast<RaspLuaEngine *>(lua_touserdata(L, -1));
    lua_pop(L, 1);

    if (eng)
        eng->Log("Calling regex match.");

    if (!eng || !pattern || !text)
    {
        lua_pushboolean(L, 0);
        return 1;
    }

    lua_getfield(L, LUA_REGISTRYINDEX, kLuaBudgetRegistryKey);
    auto *exec = static_cast<ScanExecutionContext *>(lua_touserdata(L, -1));
    lua_pop(L, 1);

    if (exec && !exec->TryEnterRegexCall())
    {
        lua_pushboolean(L, 0);
        return 1;
    }
    if (exec)
        textLen = exec->BoundedRegexSubjectLength(textLen);

    pcre2_code *re = eng->GetOrCompilePcre2(std::string(pattern));
    if (!re)
    {
        lua_pushboolean(L, 0);
        return 1;
    }

    pcre2_match_context *mctx = CreateBudgetedMatchContext(exec);

    pcre2_match_data *md = pcre2_match_data_create_from_pattern(re, nullptr);
    int rc = md ? pcre2_match(re,
                              reinterpret_cast<PCRE2_SPTR8>(text), textLen,
                              0, 0, md, mctx)
                : PCRE2_ERROR_NOMATCH;

    if (md)
        pcre2_match_data_free(md);
    if (mctx)
        pcre2_match_context_free(mctx);

    RecordRegexLimit(rc, exec);
    lua_pushboolean(L, rc >= 0 ? 1 : 0);
    return 1;
}

static int lua_pcre2_capture(lua_State *L)
{
    // regex_capture(pattern, text) → string (first capture group) | nil
    const char *pattern = luaL_checkstring(L, 1);
    size_t textLen = 0;
    const char *text = luaL_checklstring(L, 2, &textLen);

    lua_getfield(L, LUA_REGISTRYINDEX, "rasp_engine");
    auto *eng = static_cast<RaspLuaEngine *>(lua_touserdata(L, -1));
    lua_pop(L, 1);

    if (!eng || !pattern || !text)
    {
        lua_pushnil(L);
        return 1;
    }

    lua_getfield(L, LUA_REGISTRYINDEX, kLuaBudgetRegistryKey);
    auto *exec = static_cast<ScanExecutionContext *>(lua_touserdata(L, -1));
    lua_pop(L, 1);

    if (exec && !exec->TryEnterRegexCall())
    {
        lua_pushnil(L);
        return 1;
    }
    if (exec)
        textLen = exec->BoundedRegexSubjectLength(textLen);

    pcre2_code *re = eng->GetOrCompilePcre2(std::string(pattern));
    if (!re)
    {
        lua_pushnil(L);
        return 1;
    }

    pcre2_match_context *mctx = CreateBudgetedMatchContext(exec);

    pcre2_match_data *md = pcre2_match_data_create_from_pattern(re, nullptr);
    if (!md)
    {
        if (mctx)
            pcre2_match_context_free(mctx);
        lua_pushnil(L);
        return 1;
    }

    int rc = pcre2_match(re,
                         reinterpret_cast<PCRE2_SPTR8>(text), textLen,
                         0, 0, md, mctx);
    RecordRegexLimit(rc, exec);

    if (rc >= 2) // rc = number of capture pairs captured; >= 2 means group 1 matched
    {
        PCRE2_SIZE *ov = pcre2_get_ovector_pointer(md);
        PCRE2_SIZE s = ov[2]; // group 1 start
        PCRE2_SIZE e = ov[3]; // group 1 end
        if (s != PCRE2_UNSET && e >= s)
            lua_pushlstring(L, text + s, e - s);
        else
            lua_pushnil(L);
    }
    else
    {
        lua_pushnil(L);
    }

    pcre2_match_data_free(md);
    if (mctx)
        pcre2_match_context_free(mctx);

    return 1;
}

#endif // RASP_PCRE2_AVAILABLE

// ── Instruction-count timeout hook ────────────────────────────────────────────
// 超市熔断机制:防止lua脚本死循环; Verbatim from amsi_rule_engine.cpp / rasp_lua_engine.cpp.
static void LuaTimeoutHook(lua_State *L, lua_Debug *)
{
    luaL_error(L, "script timeout");
}

static void LuaBudgetHook(lua_State *L, lua_Debug *)
{
    lua_getfield(L, LUA_REGISTRYINDEX, kLuaBudgetRegistryKey);
    auto *exec = static_cast<ScanExecutionContext *>(lua_touserdata(L, -1));
    lua_pop(L, 1);

    if (exec && !exec->AddLuaInstructions(kLuaHookInstructionStep))
        luaL_error(L, "lua budget timeout");
}

static void ClearLuaBudgetHook(lua_State *L)
{
    lua_sethook(L, nullptr, 0, 0);
    lua_pushnil(L);
    lua_setfield(L, LUA_REGISTRYINDEX, kLuaBudgetRegistryKey);
}

// ── print() → module log backend ─────────────────────────────────────────────
// 功能：劫持 Lua 的 print()，将输出格式化后，通过底层的 Log() 塞入 C++ 环形缓冲区，最终发给后端，方便安全人员调试。
static int LuaPrint(lua_State *L)
{
    int n = lua_gettop(L);
    char buf[512];
    int pos = 0;

    for (int i = 1; i <= n && pos < (int)sizeof(buf) - 2; i++)
    {
        if (i > 1 && pos < (int)sizeof(buf) - 2)
            buf[pos++] = '\t';

        size_t len = 0;
        const char *s = lua_tolstring(L, i, &len);
        if (!s)
            s = "(nil)";
        int room = (int)sizeof(buf) - pos - 2;
        if (room > 0)
        {
            int copy = (int)len < room ? (int)len : room;
            memcpy(buf + pos, s, (size_t)copy);
            pos += copy;
        }
    }
    buf[pos++] = '\n';
    buf[pos] = '\0';

    // Route through the engine's log function stored in Lua registry
    lua_getfield(L, LUA_REGISTRYINDEX, "rasp_engine");
    auto *eng = static_cast<RaspLuaEngine *>(lua_touserdata(L, -1));
    lua_pop(L, 1);
    if (eng)
        eng->Log(buf);
    else
        OutputDebugStringA(buf);

    return 0;
}

// ── RaspLuaEngine::Precompile ─────────────────────────────────────────────────
// 功能：在收到规则配置时，提前进行语法检查。
// 流程：创建临时 Lua State -> luaL_loadbuffer 检查语法 -> 如果 OK，将源码存入 m_sources。
void RaspLuaEngine::Precompile(const std::string &ruleId,
                               const std::string &payload,
                               bool isBytecode)
{
    if (ruleId.empty() || payload.empty())
        return;

    if (isBytecode) {
        if (!IsLua54BytecodePayload(payload)) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "[RaspLuaEngine] Precompile: rule=%s bytecode header invalid\n",
                     ruleId.c_str());
            Log(msg);
            return;
        }

        {
            std::lock_guard<std::mutex> lk(m_mutex);
            m_sources[ruleId] = payload;
        }

        char msg[256];
        snprintf(msg, sizeof(msg), "[RaspLuaEngine] Precompile: rule=%s bytecode cached (%zu bytes)\n",
                 ruleId.c_str(), payload.size());
        Log(msg);
        return;
    }

    // 性能问题: 每次执行一条 Lua 规则，代码都会 luaL_newstate() 创建一个全新的虚拟机，加载标准库，然后再销毁它，lua太多会导致cpu损耗
    lua_State *L = luaL_newstate();
    if (!L)
    {
        char msg[256];
        snprintf(msg, sizeof(msg), "[RaspLuaEngine] Precompile: luaL_newstate failed rule=%s\n",
                 ruleId.c_str());
        Log(msg);
        return;
    }

    if (luaL_loadbuffer(L, payload.data(), payload.size(),
                        ruleId.c_str()) != LUA_OK)
    {
        const char *err = lua_tostring(L, -1);
        char msg[512];
        snprintf(msg, sizeof(msg), "[RaspLuaEngine] Precompile: rule=%s syntax error: %s\n",
                 ruleId.c_str(), err ? err : "(null)");
        Log(msg);
        lua_close(L);
        return; // do not cache — IsLoaded returns false → C++ fallback
    }

    lua_close(L);

    // Cache the combined source text
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        m_sources[ruleId] = payload;
    }

    char msg[256];
    snprintf(msg, sizeof(msg), "[RaspLuaEngine] Precompile: rule=%s cached (%zu bytes)\n",
             ruleId.c_str(), payload.size());
    Log(msg);
}

// ── RaspLuaEngine::IsLoaded ───────────────────────────────────────────────────

bool RaspLuaEngine::IsLoaded(const std::string &ruleId) const
{
    std::lock_guard<std::mutex> lk(m_mutex);
    return m_sources.count(ruleId) != 0;
}

// ── RaspLuaEngine::Reset ──────────────────────────────────────────────────────

void RaspLuaEngine::Reset()
{
    std::lock_guard<std::mutex> lk(m_mutex);
    m_sources.clear();
}

// ── RaspLuaEngine::Run ────────────────────────────────────────────────────────

RaspLuaResult RaspLuaEngine::Run(
    const std::string &ruleId,
    const std::string &sensorName,
    const RaspLuaContext &ctx,
    int timeoutInstructions,
    const std::vector<std::string> &matchedCheckIds,
    ScanExecutionContext *exec)
{
    RaspLuaResult result;

    // 获取规则源码
    std::string payload;
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        auto it = m_sources.find(ruleId);
        if (it == m_sources.end())
            return result;
        payload = it->second;
    }

    // ── Phase 0: 创建全新虚拟机 ─────────────────────────────────────────────────
    lua_State *L = luaL_newstate();
    if (!L)
        return result;

    // Store engine pointer in Lua registry so LuaPrint can call Log()
    lua_pushlightuserdata(L, this);
    lua_setfield(L, LUA_REGISTRYINDEX, "rasp_engine");

    // ── Phase 1: 加载基础库 ───────────────────────────────────────────────
    luaopen_base(L);
    luaopen_string(L);
    luaopen_math(L);
    luaopen_table(L);

    // ── Phase 2: 不安全的函数设置为nil(严格沙箱化) ───────────────────────────────────────
    const char *unsafe[] = {
        "dofile", "loadfile", "require",
        "collectgarbage", "rawset", "io", "os", "package", nullptr};
    for (int k = 0; unsafe[k]; k++)
    {
        lua_pushnil(L);
        lua_setglobal(L, unsafe[k]);
    }

    // ── Phase 3: 注入print, regex_match 和超时 Hook ───────────────────────────
    lua_pushcfunction(L, LuaPrint);
    lua_setglobal(L, "print");

    // ── Phase 3b: register PCRE2 regex globals (when PCRE2 is available) ────────
#ifdef RASP_PCRE2_AVAILABLE
    lua_pushcfunction(L, lua_pcre2_match);
    lua_setglobal(L, "regex_match");
    lua_pushcfunction(L, lua_pcre2_capture);
    lua_setglobal(L, "regex_capture");
#endif

    // ── Phase 4: set instruction-count timeout ────────────────────────────────
    if (exec) {
        exec->luaDeadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec->budget.luaBudgetMs));
        exec->luaDeadlineActive = true;
        lua_pushlightuserdata(L, exec);
        lua_setfield(L, LUA_REGISTRYINDEX, kLuaBudgetRegistryKey);
        lua_sethook(L, LuaBudgetHook, LUA_MASKCOUNT, static_cast<int>(kLuaHookInstructionStep));
    } else {
        if (timeoutInstructions <= 0)
            timeoutInstructions = 500000;
        lua_sethook(L, LuaTimeoutHook, LUA_MASKCOUNT, timeoutInstructions);
    }

    // ── Phase 5: luaL_loadbuffer + lua_pcall 编译并执行外层包裹，注册 rule 函数 ──────────────
    const bool isBytecode = IsLua54BytecodePayload(payload);
    int loadStatus = LUA_ERRSYNTAX;
    if (isBytecode)
    {
        LuaBytecodeReader reader{payload.data(), payload.size(), false};
        loadStatus = lua_load(L, ReadLuaBytecode, &reader, ruleId.c_str(), "b");
    }
    else
    {
        loadStatus = luaL_loadbuffer(L, payload.data(), payload.size(), ruleId.c_str());
    }

    if (loadStatus != LUA_OK)
    {
        const char *err = lua_tostring(L, -1);
        char msg[512];
        snprintf(msg, sizeof(msg), "[RaspLuaEngine] Run: rule=%s load(%s): %s\n",
                 ruleId.c_str(), isBytecode ? "bytecode" : "source", err ? err : "(null)");
        Log(msg);
        ClearLuaBudgetHook(L);
        lua_close(L);
        return result;
    }
    if (lua_pcall(L, 0, 0, 0) != LUA_OK)
    {
        const char *err = lua_tostring(L, -1);
        char msg[512];
        snprintf(msg, sizeof(msg), "[RaspLuaEngine] Run: rule=%s chunk exec: %s\n",
                 ruleId.c_str(), err ? err : "(null)");
        Log(msg);
        if (exec && exec->timedOut) {
            result.timedOut = true;
            result.timeoutReason = exec->timeoutReason;
        }
        ClearLuaBudgetHook(L);
        lua_close(L);
        return result;
    }

    // ── Phase 6: resolve rule() function ─────────────────────────────────────
    lua_getglobal(L, "rule");
    if (lua_type(L, -1) != LUA_TFUNCTION)
    {
        char msg[256];
        snprintf(msg, sizeof(msg), "[RaspLuaEngine] Run: rule=%s 'rule' is not a function\n",
                 ruleId.c_str());
        Log(msg);
        ClearLuaBudgetHook(L);
        lua_close(L);
        return result;
    }

    // ── Phase 7: push sensor name arg ────────────────────────────────────────
    lua_pushstring(L, sensorName.c_str());

    // ── Phase 8: 将 ctx.fields 转化为 Lua 的 Table ───────────────────────────
    // Only the fields this module populated are pushed — no cross-module leakage.
    lua_newtable(L);

    for (const auto &f : ctx.fields)
    {
        if (f.isBinary)
            lua_pushlstring(L, f.value.data(), f.value.size());
        else
            lua_pushstring(L, f.value.c_str());
        lua_setfield(L, -2, f.name.c_str());
    }

    // Optional 1-indexed Lua array (e.g. context.patterns for IIS7)
    if (ctx.arrayField && !ctx.arrayField->empty())
    {
        lua_newtable(L);
        int idx = 1;
        for (const auto &p : *ctx.arrayField)
        {
            lua_pushstring(L, p.c_str());
            lua_rawseti(L, -2, idx++);
        }
        lua_setfield(L, -2, ctx.arrayFieldName.c_str());
    }

    // regex_matches — 1-indexed array of matched regexCheck IDs (may be empty).
    // Scripts access this as context.regex_matches to branch on which checks fired.
    if (!matchedCheckIds.empty())
    {
        lua_newtable(L);
        int idx = 1;
        for (const auto &id : matchedCheckIds)
        {
            lua_pushstring(L, id.c_str());
            lua_rawseti(L, -2, idx++);
        }
        lua_setfield(L, -2, "regex_matches");
    }

    // ── Phase 9: call rule(sensor, context) ──────────────────────────────────
    if (lua_pcall(L, 2, 1, 0) != LUA_OK)
    {
        const char *err = lua_tostring(L, -1);
        char msg[512];
        snprintf(msg, sizeof(msg), "[RaspLuaEngine] Run: rule=%s call error: %s\n",
                 ruleId.c_str(), err ? err : "(null)");
        Log(msg);
        if (exec && exec->timedOut) {
            result.timedOut = true;
            result.timeoutReason = exec->timeoutReason;
        }
        ClearLuaBudgetHook(L);
        lua_close(L);
        return result;
    }

    // ── Phase 10: parse result table { match=bool, desc=str, payload=str } ───
    if (lua_istable(L, -1))
    {
        lua_getfield(L, -1, "match");
        result.matched = (lua_toboolean(L, -1) != 0);
        lua_pop(L, 1);

        lua_getfield(L, -1, "desc");
        if (lua_isstring(L, -1))
            result.desc = lua_tostring(L, -1);
        lua_pop(L, 1);

        lua_getfield(L, -1, "payload");
        if (lua_isstring(L, -1))
            result.payload = lua_tostring(L, -1);
        lua_pop(L, 1);
    }

    if (result.matched)
    {
        char msg[512];
        snprintf(msg, sizeof(msg), "[RaspLuaEngine] Run: rule=%s MATCH desc=%s\n",
                 ruleId.c_str(), result.desc.c_str());
        Log(msg);
    }

    ClearLuaBudgetHook(L);
    lua_close(L);
    return result;
}
