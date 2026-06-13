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

    int SafeLuaPCall(lua_State* L, int nargs, int nresults, int errfunc)
    {
        __try {
            return lua_pcall(L, nargs, nresults, errfunc);
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return LUA_ERRRUN;
        }
    }

} // namespace

// ── Destructor ────────────────────────────────────────────────────────────────
// 释放 PCRE2 预编译的正则表达式对象。使用了 std::lock_guard 保证线程安全释放。
RaspLuaEngine::~RaspLuaEngine()
{
#ifdef RASP_PCRE2_AVAILABLE
    std::lock_guard<std::mutex> lk(m_regexMutex);
    for (auto &kv : m_regexCache)
        pcre2_code_free(reinterpret_cast<pcre2_code*>(kv.second.code));
    m_regexCache.clear();
#endif
}

// ── Log routing ───────────────────────────────────────────────────────────────

void RaspLuaEngine::SetLogFn(RaspLuaLogFn fn)
{
    m_logFn = fn;
}

void RaspLuaEngine::SetLeveledLogFn(RaspLuaLeveledLogFn fn)
{
    m_leveledLogFn = fn;
}

void RaspLuaEngine::Log(const char *msg) const
{
    LogWithSeverity(RaspDiagSeverity::Info, msg);
}

void RaspLuaEngine::LogWithSeverity(RaspDiagSeverity severity, const char *msg) const
{
    if (m_leveledLogFn) {
        m_leveledLogFn(severity, msg);
    } else if (m_logFn) {
        m_logFn(msg);
    } else {
        OutputDebugStringA(msg); // safe fallback before SetLogFn
    }
}

#ifdef RASP_PCRE2_AVAILABLE

namespace {

int SafePcre2Match(pcre2_code* re,
                   PCRE2_SPTR8 subject,
                   PCRE2_SIZE length,
                   PCRE2_SIZE startOffset,
                   uint32_t options,
                   pcre2_match_data* matchData,
                   pcre2_match_context* matchContext)
{
    __try {
        return pcre2_match(re, subject, length, startOffset, options, matchData, matchContext);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return PCRE2_ERROR_INTERNAL;
    }
}

struct Pcre2ThreadContextCache
{
    pcre2_match_context* matchContext = nullptr;
    pcre2_jit_stack* jitStack = nullptr;
    bool initialized = false;

    bool Init()
    {
        if (initialized)
            return true;

        matchContext = pcre2_match_context_create(nullptr);
        if (!matchContext)
            return false;

        jitStack = pcre2_jit_stack_create(32 * 1024, 512 * 1024, nullptr);
        if (jitStack)
            pcre2_jit_stack_assign(matchContext, nullptr, jitStack);
        initialized = true;
        return true;
    }

    void SetBudgetLimits(const ScanExecutionContext* exec)
    {
        if (!matchContext)
            return;

        if (exec) {
            pcre2_set_match_limit(matchContext, exec->budget.pcre2MatchLimit);
            pcre2_set_depth_limit(matchContext, exec->budget.pcre2DepthLimit);
            pcre2_set_heap_limit(matchContext, exec->budget.pcre2HeapLimitKiB);
        } else {
            pcre2_set_match_limit(matchContext, 500000);
        }
    }

    ~Pcre2ThreadContextCache()
    {
        if (jitStack)
            pcre2_jit_stack_free(jitStack);
        if (matchContext)
            pcre2_match_context_free(matchContext);
    }
};

static thread_local Pcre2ThreadContextCache t_pcre2ThreadContext;

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

pcre2_match_context* AcquireBudgetedMatchContext(const ScanExecutionContext* exec, bool& mustFree)
{
    mustFree = false;
    if (t_pcre2ThreadContext.Init()) {
        t_pcre2ThreadContext.SetBudgetLimits(exec);
        return t_pcre2ThreadContext.matchContext;
    }

    mustFree = true;
    return CreateBudgetedMatchContext(exec);
}

void ReleaseBudgetedMatchContext(pcre2_match_context* mctx, bool mustFree)
{
    if (mustFree && mctx)
        pcre2_match_context_free(mctx);
}

void RecordRegexLimit(int rc, ScanExecutionContext* exec)
{
    if (!exec)
        return;

    if (rc == PCRE2_ERROR_MATCHLIMIT) {
        exec->MarkRuleLimit("regex_pattern_limit", "match_limit");
    } else if (rc == PCRE2_ERROR_JIT_STACKLIMIT) {
        exec->MarkRuleLimit("regex_pattern_limit", "jit_stack_limit");
    } else if (rc == PCRE2_ERROR_DEPTHLIMIT) {
        exec->MarkRuleLimit("regex_pattern_limit", "depth_limit");
    } else if (rc == PCRE2_ERROR_HEAPLIMIT) {
        exec->MarkRuleLimit("regex_pattern_limit", "heap_limit");
    }
}


const char* RegexErrorName(int rc)
{
    switch (rc) {
    case PCRE2_ERROR_NOMATCH:
        return "nomatch";
    case PCRE2_ERROR_MATCHLIMIT:
        return "match_limit";
    case PCRE2_ERROR_JIT_STACKLIMIT:
        return "jit_stack_limit";
    case PCRE2_ERROR_DEPTHLIMIT:
        return "depth_limit";
    case PCRE2_ERROR_HEAPLIMIT:
        return "heap_limit";
    case PCRE2_ERROR_NOMEMORY:
        return "no_memory";
    case PCRE2_ERROR_BADOPTION:
        return "bad_option";
    case PCRE2_ERROR_BADMODE:
        return "bad_mode";
    default:
        return "pcre2_error";
    }
}

bool ShouldLogRegexFailure(int rc)
{
    return rc != PCRE2_ERROR_NOMATCH;
}

RaspDiagSeverity RegexFailureSeverity(int rc)
{
    if (rc == PCRE2_ERROR_MATCHLIMIT || rc == PCRE2_ERROR_JIT_STACKLIMIT ||
        rc == PCRE2_ERROR_DEPTHLIMIT || rc == PCRE2_ERROR_HEAPLIMIT)
        return RaspDiagSeverity::Warning;
    return RaspDiagSeverity::Error;
}

void LogRegexFailure(const RaspLuaEngine* engine,
                     const char* api,
                     int rc,
                     const std::string& pattern,
                     size_t subjectLen,
                     const ScanExecutionContext* exec)
{
    if (!engine || !ShouldLogRegexFailure(rc))
        return;
    (void)pattern;

    const char* reason = "none";
    const char* limitType = "none";
    int ruleIndex = -1;
    int checkIndex = -1;
    int patternIndex = -1;
    if (exec) {
        if (!exec->currentRuleLimitReason.empty())
            reason = exec->currentRuleLimitReason.c_str();
        else if (!exec->timeoutReason.empty())
            reason = exec->timeoutReason.c_str();

        if (!exec->currentRuleLimitType.empty())
            limitType = exec->currentRuleLimitType.c_str();
        else if (!exec->regexLimitType.empty())
            limitType = exec->regexLimitType.c_str();

        ruleIndex = exec->currentRuleIndex;
        checkIndex = exec->currentRegexCheckIndex;
        patternIndex = exec->currentRegexPatternIndex;
    }

    char msg[512];
    snprintf(msg, sizeof(msg),
             "[AmsiLuaEngine] regex failure api=%s rc=%d error=%s subjectLen=%zu regexCalls=%u timedOut=%d reason=%s limitType=%s ruleIndex=%d checkIndex=%d patternIndex=%d",
             api ? api : "unknown",
             rc,
             RegexErrorName(rc),
             subjectLen,
             exec ? exec->regexCalls : 0,
             exec && exec->timedOut ? 1 : 0,
             reason,
             limitType,
             ruleIndex,
             checkIndex,
             patternIndex);
    engine->LogWithSeverity(RegexFailureSeverity(rc), msg);
}

} // namespace

/*
 * 首次使用时编译模式；后续调用返回缓存的代码对象。
 * 尝试JIT编译，但如果不可用，则会自动跳过（例如，在不支持PCRE2 JIT的平台/架构上）。
 * 在MatchesAnyRegex和Lua绑定中，每次调用的匹配限制为500000步，这限制了任何病理模式的回溯（正则的ddos攻击）。
 * 流程: 先查锁，如果缓存有直接返回 -> 编译正则 -> 尝试开启 PCRE2_JIT_COMPLETE 硬件级加速 -> 存入缓存 m_regexCache
 * */
/*
 * 函数说明: 编译或复用一个 PCRE2 正则表达式，并把可用于快速拒绝的元数据写入缓存。
 * 输入:
 *   pattern - 规则中的 PCRE2 正则表达式字符串。
 * 输出:
 *   返回已编译的 pcre2_code 指针；如果 pattern 非法或编译失败，返回 nullptr。
 * 重点步骤:
 *   1. 先查快照级缓存，命中则直接返回已编译对象。
 *   2. 未命中时编译 pattern，并尝试执行 JIT 编译。
 *   3. 通过 pcre2_pattern_info 自动提取 firstCodeType、firstCodeUnit、firstBitmap、minLength。
 *   4. 将 compiled code 和元数据作为 CompiledRegexEntry 原子写入缓存。
 */
pcre2_real_code_8 *RaspLuaEngine::GetOrCompilePcre2(const std::string &pattern,
                                                     const RegexCompileContext* context) const
{
    {
        std::lock_guard<std::mutex> lk(m_regexMutex);
        auto it = m_regexCache.find(pattern);
        if (it != m_regexCache.end())
            return it->second.code;
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
        const int ruleIndex = context ? context->ruleIndex : -1;
        const int checkIndex = context ? context->checkIndex : -1;
        const int patternIndex = context ? context->patternIndex : -1;
        snprintf(msg, sizeof(msg),
                 "[AmsiLuaEngine] regex compile error at offset %zu: %s ruleIndex=%d checkIndex=%d patternIndex=%d\n",
                 (size_t)erroffset,
                 reinterpret_cast<const char *>(errbuf),
                 ruleIndex,
                 checkIndex,
                 patternIndex);
        Log(msg);
        return nullptr;
    }

    // Best-effort JIT; continues without JIT if platform doesn't support it.
    pcre2_jit_compile(re, PCRE2_JIT_COMPLETE);

    CompiledRegexEntry entry;
    entry.code = reinterpret_cast<pcre2_real_code_8*>(re);

    /*
     * 提取 PCRE2 自动计算出的首字符约束。
     * firstCodeType == 1 表示固定首字符；只有该字符能用单字节表示时才用于 memchr 快速拒绝。
     * 如果 firstCodeUnit 超出 0xFF，则降级为 firstCodeType == 0，保持缓存条目语义自洽。
     */
    uint32_t firstCodeType = 0;
    if (pcre2_pattern_info(re, PCRE2_INFO_FIRSTCODETYPE, &firstCodeType) == 0)
        entry.firstCodeType = firstCodeType;

    uint32_t firstCodeUnit = 0;
    if (entry.firstCodeType == 1 &&
        pcre2_pattern_info(re, PCRE2_INFO_FIRSTCODEUNIT, &firstCodeUnit) == 0) {
        if (firstCodeUnit <= 0xFF) {
            entry.firstCodeUnit = firstCodeUnit;
        } else {
            entry.firstCodeType = 0;
            entry.firstCodeUnit = 0;
        }
    }

    /*
     * firstCodeType == 2 表示 PCRE2 给出了可能首字符集合。
     * PCRE2 返回的是 32 字节 bitset，覆盖 0..255 的 256 个 byte 值；这里复制到 entry 自有内存，避免保存内部指针。
     */
    if (entry.firstCodeType == 2) {
        const uint8_t* bitmap = nullptr;
        if (pcre2_pattern_info(re, PCRE2_INFO_FIRSTBITMAP, &bitmap) == 0 && bitmap != nullptr)
            std::memcpy(entry.firstBitmap, bitmap, sizeof(entry.firstBitmap));
        else
            entry.firstCodeType = 0;
    }

    /*
     * minLength 是 PCRE2 计算出的最小可能匹配长度。
     * subject 比该长度短时可以直接跳过，不消耗 regexCalls budget。
     */
    PCRE2_SIZE minLength = 0;
    if (pcre2_pattern_info(re, PCRE2_INFO_MINLENGTH, &minLength) == 0)
        entry.minLength = static_cast<size_t>(minLength);

    {
        std::lock_guard<std::mutex> lk(m_regexMutex);
        // Check again under lock; another thread may have compiled while we did.
        auto it = m_regexCache.find(pattern);
        if (it != m_regexCache.end())
        {
            pcre2_code_free(re); // discard our copy
            return it->second.code;
        }
        m_regexCache.emplace(pattern, entry);
    }
    return reinterpret_cast<pcre2_real_code_8*>(re);
}

/*
 * 函数说明: 从正则缓存中按值取出已编译正则及其快速拒绝元数据。
 * 输入:
 *   pattern - 需要查询的正则表达式字符串。
 *   out     - 输出参数，接收 CompiledRegexEntry 的独立副本。
 * 输出:
 *   true  - 缓存命中，out 已填充。
 *   false - 参数为空或缓存未命中。
 * 说明:
 *   该函数不返回缓存内部指针，避免锁释放后 unordered_map rehash 或写入导致调用方持有悬空引用。
 */
bool RaspLuaEngine::GetCompiledRegexEntry(const std::string& pattern, CompiledRegexEntry* out) const
{
    if (!out)
        return false;
    std::lock_guard<std::mutex> lk(m_regexMutex);
    auto it = m_regexCache.find(pattern);
    if (it == m_regexCache.end())
        return false;
    *out = it->second;
    return true;
}
size_t RaspLuaEngine::RegexCacheSizeForTesting() const
{
    std::lock_guard<std::mutex> lk(m_regexMutex);
    return m_regexCache.size();
}

void RaspLuaEngine::PrecompileRegex(const std::vector<std::string>& patterns,
                                    int ruleIndex,
                                    int checkIndex) const
{
    for (size_t patternIndex = 0; patternIndex < patterns.size(); ++patternIndex) {
        const auto& pattern = patterns[patternIndex];
        if (!pattern.empty()) {
            RegexCompileContext context;
            context.ruleIndex = ruleIndex;
            context.checkIndex = checkIndex;
            context.patternIndex = static_cast<int>(patternIndex);
            (void)GetOrCompilePcre2(pattern, &context);
        }
    }
}

// ── MatchesAnyRegex ───────────────────────────────────────────────────────────

/*
 * 函数说明: 使用 C++ PCRE2 路径按顺序匹配多个正则表达式。
 * 输入:
 *   patterns          - 待匹配的正则表达式列表。
 *   text              - 本次 Scan 的检测文本。
 *   matchedPatternOut - 输出参数，命中时写入第一个命中的 pattern。
 *   exec              - 可选的扫描预算/telemetry 上下文，用于统计 regexCalls、regexPrefixSkips 和超时状态。
 * 输出:
 *   true  - 任意 pattern 命中。
 *   false - 没有命中、pattern 编译失败、预算耗尽或当前规则遇到 PCRE2 资源限制。
 * 重点步骤:
 *   1. 对 text 按 maxRegexSubjectBytes 做长度上限裁剪。
 *   2. 获取已编译正则和 firstCode/minLength 元数据。
 *   3. 先执行 literal-prefix fast reject；被拒绝的 pattern 不消耗 regexCalls budget。
 *   4. 只有无法快速拒绝的 pattern 才进入 TryEnterRegexCall 和 pcre2_match。
 */
bool RaspLuaEngine::MatchesAnyRegex(const std::vector<std::string> &patterns,
                                     const std::string &text,
                                     std::string &matchedPatternOut,
                                     ScanExecutionContext *exec) const
{
    size_t subjectLen = exec ? exec->BoundedRegexSubjectLength(text.size()) : text.size();
    const char* subjectPtr = text.data();
    for (size_t patternIndex = 0; patternIndex < patterns.size(); ++patternIndex)
    {
        const auto &pat = patterns[patternIndex];
        if (pat.empty())
            continue;

        if (exec)
            exec->SetRegexPatternIndex(static_cast<int>(patternIndex));

        RegexCompileContext compileContext;
        if (exec) {
            compileContext.ruleIndex = exec->currentRuleIndex;
            compileContext.checkIndex = exec->currentRegexCheckIndex;
            compileContext.patternIndex = exec->currentRegexPatternIndex;
        } else {
            compileContext.patternIndex = static_cast<int>(patternIndex);
        }
        pcre2_code *re = reinterpret_cast<pcre2_code*>(GetOrCompilePcre2(pat, &compileContext));
        if (!re)
            continue;

        CompiledRegexEntry entry;
        bool hasEntry = GetCompiledRegexEntry(pat, &entry);
        bool fastRejected = false;

        if (hasEntry) {
            /* 当前文本短于正则最小匹配长度，必然无法命中，直接跳过。 */
            if (entry.minLength > 0 && subjectLen < entry.minLength) {
                fastRejected = true;
            } else if (entry.firstCodeType == 1 && entry.firstCodeUnit <= 0xFF) {
                fastRejected = std::memchr(subjectPtr,
                                           static_cast<unsigned char>(entry.firstCodeUnit),
                                           subjectLen) == nullptr;
            } else if (entry.firstCodeType == 2) {
                /* bitmap 是 32 字节 bitset；只要文本里没有任何可能首字符，就可以安全跳过完整匹配。 */
                bool foundPossibleFirstByte = false;
                for (size_t i = 0; i < subjectLen; ++i) {
                    const uint8_t ch = static_cast<uint8_t>(subjectPtr[i]);
                    if ((entry.firstBitmap[ch >> 3] & static_cast<uint8_t>(1u << (ch & 7))) != 0) {
                        foundPossibleFirstByte = true;
                        break;
                    }
                }
                fastRejected = !foundPossibleFirstByte;
            }
        }

        if (fastRejected) {
            if (exec)
                ++exec->regexPrefixSkips;
            continue;
        }

        /* 只有真实进入 pcre2_match 的 pattern 才消耗 regexCalls budget。 */
        if (exec && !exec->TryEnterRegexCall()) {
            LogRegexFailure(this, "MatchesAnyRegex", PCRE2_ERROR_MATCHLIMIT, pat, subjectLen, exec);
            return false;
        }

        bool mustFreeMctx = false;
        pcre2_match_context *mctx = AcquireBudgetedMatchContext(exec, mustFreeMctx);
        if (!mctx)
        {
            LogRegexFailure(this, "MatchesAnyRegex", PCRE2_ERROR_NOMEMORY, pat, subjectLen, exec);
            continue;
        }

        pcre2_match_data *md = pcre2_match_data_create_from_pattern(re, nullptr);
        if (!md)
        {
            LogRegexFailure(this, "MatchesAnyRegex", PCRE2_ERROR_NOMEMORY, pat, subjectLen, exec);
            ReleaseBudgetedMatchContext(mctx, mustFreeMctx);
            continue;
        }

        int rc = SafePcre2Match(
            re,
            reinterpret_cast<PCRE2_SPTR8>(subjectPtr),
            subjectLen,
            0, // start offset
            0, // options
            md,
            mctx);

        pcre2_match_data_free(md);
        ReleaseBudgetedMatchContext(mctx, mustFreeMctx);

        if (rc >= 0)
        {
            matchedPatternOut = pat;
            return true;
        }
        RecordRegexLimit(rc, exec);
        LogRegexFailure(this, "MatchesAnyRegex", rc, pat, subjectLen, exec);
        if (exec && exec->currentRuleLimited)
            return false;
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

    if (!eng || !pattern || !text)
    {
        lua_pushboolean(L, 0);
        return 1;
    }

    lua_getfield(L, LUA_REGISTRYINDEX, kLuaBudgetRegistryKey);
    auto *exec = static_cast<ScanExecutionContext *>(lua_touserdata(L, -1));
    lua_pop(L, 1);
    if (exec)
        exec->SetRegexPatternIndex(-1);

    if (exec && !exec->TryEnterRegexCall())
    {
        LogRegexFailure(eng, "lua_regex_match", PCRE2_ERROR_MATCHLIMIT, std::string(pattern), textLen, exec);
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

    bool mustFreeMctx = false;
    pcre2_match_context *mctx = AcquireBudgetedMatchContext(exec, mustFreeMctx);
    if (!mctx)
    {
        LogRegexFailure(eng, "lua_regex_match", PCRE2_ERROR_NOMEMORY, std::string(pattern), textLen, exec);
        lua_pushboolean(L, 0);
        return 1;
    }

    pcre2_match_data *md = pcre2_match_data_create_from_pattern(re, nullptr);
    int rc = md ? SafePcre2Match(re,
                                 reinterpret_cast<PCRE2_SPTR8>(text), textLen,
                                 0, 0, md, mctx)
                : PCRE2_ERROR_NOMEMORY;

    if (md)
        pcre2_match_data_free(md);
    ReleaseBudgetedMatchContext(mctx, mustFreeMctx);

    RecordRegexLimit(rc, exec);
    LogRegexFailure(eng, "lua_regex_match", rc, std::string(pattern), textLen, exec);
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
    if (exec)
        exec->SetRegexPatternIndex(-1);

    if (exec && !exec->TryEnterRegexCall())
    {
        LogRegexFailure(eng, "lua_regex_capture", PCRE2_ERROR_MATCHLIMIT, std::string(pattern), textLen, exec);
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

    bool mustFreeMctx = false;
    pcre2_match_context *mctx = AcquireBudgetedMatchContext(exec, mustFreeMctx);
    if (!mctx)
    {
        LogRegexFailure(eng, "lua_regex_capture", PCRE2_ERROR_NOMEMORY, std::string(pattern), textLen, exec);
        lua_pushnil(L);
        return 1;
    }

    pcre2_match_data *md = pcre2_match_data_create_from_pattern(re, nullptr);
    if (!md)
    {
        LogRegexFailure(eng, "lua_regex_capture", PCRE2_ERROR_NOMEMORY, std::string(pattern), textLen, exec);
        ReleaseBudgetedMatchContext(mctx, mustFreeMctx);
        lua_pushnil(L);
        return 1;
    }

    int rc = SafePcre2Match(re,
                            reinterpret_cast<PCRE2_SPTR8>(text), textLen,
                            0, 0, md, mctx);
    RecordRegexLimit(rc, exec);
    LogRegexFailure(eng, "lua_regex_capture", rc, std::string(pattern), textLen, exec);

    if (rc >= 2)
    {
        PCRE2_SIZE *ov = pcre2_get_ovector_pointer(md);
        PCRE2_SIZE s = ov[2];
        PCRE2_SIZE e = ov[3];
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
    ReleaseBudgetedMatchContext(mctx, mustFreeMctx);

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
                     "[AmsiLuaEngine] Precompile: rule=%s bytecode header invalid\n",
                     ruleId.c_str());
            Log(msg);
            return;
        }

        {
            std::lock_guard<std::mutex> lk(m_mutex);
            m_sources[ruleId] = payload;
        }

        char msg[256];
        snprintf(msg, sizeof(msg), "[AmsiLuaEngine] Precompile: rule=%s bytecode cached (%zu bytes)\n",
                 ruleId.c_str(), payload.size());
        Log(msg);
        return;
    }

    // 性能问题: 每次执行一条 Lua 规则，代码都会 luaL_newstate() 创建一个全新的虚拟机，加载标准库，然后再销毁它，lua太多会导致cpu损耗
    lua_State *L = luaL_newstate();
    if (!L)
    {
        char msg[256];
        snprintf(msg, sizeof(msg), "[AmsiLuaEngine] Precompile: luaL_newstate failed rule=%s\n",
                 ruleId.c_str());
        Log(msg);
        return;
    }

    if (luaL_loadbuffer(L, payload.data(), payload.size(),
                        ruleId.c_str()) != LUA_OK)
    {
        const char *err = lua_tostring(L, -1);
        char msg[512];
        snprintf(msg, sizeof(msg), "[AmsiLuaEngine] Precompile: rule=%s syntax error: %s\n",
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
    snprintf(msg, sizeof(msg), "[AmsiLuaEngine] Precompile: rule=%s cached (%zu bytes)\n",
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
        snprintf(msg, sizeof(msg), "[AmsiLuaEngine] Run: rule=%s load(%s): %s\n",
                 ruleId.c_str(), isBytecode ? "bytecode" : "source", err ? err : "(null)");
        Log(msg);
        ClearLuaBudgetHook(L);
        lua_close(L);
        return result;
    }
    if (SafeLuaPCall(L, 0, 0, 0) != LUA_OK)
    {
        const char *err = lua_tostring(L, -1);
        char msg[512];
        snprintf(msg, sizeof(msg), "[AmsiLuaEngine] Run: rule=%s chunk exec: %s\n",
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
        snprintf(msg, sizeof(msg), "[AmsiLuaEngine] Run: rule=%s 'rule' is not a function\n",
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
    if (SafeLuaPCall(L, 2, 1, 0) != LUA_OK)
    {
        const char *err = lua_tostring(L, -1);
        char msg[512];
        snprintf(msg, sizeof(msg), "[AmsiLuaEngine] Run: rule=%s call error: %s\n",
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
        snprintf(msg, sizeof(msg), "[AmsiLuaEngine] Run: rule=%s MATCH desc=%s\n",
                 ruleId.c_str(), result.desc.c_str());
        Log(msg);
    }

    ClearLuaBudgetHook(L);
    lua_close(L);
    return result;
}
