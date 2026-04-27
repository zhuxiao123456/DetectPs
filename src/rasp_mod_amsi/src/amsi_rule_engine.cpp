/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */
// =========================================================================
// C++拦截层与动态安全策略之间的桥梁
// amsi_rule_engine.cpp — 规则加载、lua检测、热加载
//
// Derives from RaspSentryBase which owns:
//   ring-buffer log, ConnectSentry IPC, ParseRulesJson, LogForwardThread,
//   ConfigPipeThread, SentryRetryThread, Initialize/Shutdown,
//   SendDetectionEvent.
//
// This file provides:
//   WideToUtf8()          — local UTF-8 conversion helper
//   ParseAndSwap()        — builds AmsiRaspRuleConfig snapshot, precompiles Lua
//   OnReloadSignal()      — retries sentry on config reload signal
//   Evaluate(sensor, ctx) — iterates rules, runs Lua, fires detection events
//   Evaluate(wchar_t*,..) — AMSI public surface; converts+dispatches above
//   PrecompileAll()       — Lua precompile pass after every load
//   SwapRules()           — atomic snapshot replacement
// =========================================================================

#include "../include/amsi_rule_engine.h"
#include "../include/engine_runtime.h"

#include <algorithm>
#include <cstdarg>
#define DEFAULT_CONFIDENCE 70
// ── WideToUtf8 ────────────────────────────────────────────────────────────
static std::string WideToUtf8(const wchar_t *w) {
    if (!w || w[0] == L'\0')
        return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (len <= 0)
        return {};
    std::string s(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, &s[0], len, nullptr, nullptr);
    return s;
}

// ── ParseRuleExtension ────────────────────────────────────────────────────
/*
 * 处理“config”JSON子对象以提取基类正则表达式字段（regexField、regexPatterns）。
 * 跳过任何其他配置键——除了RaspRuleBase中的配置外，AMSI规则没有特定于模块的配置
 * */
void AmsiRuleEngine::ParseRuleExtension(const std::string &key,
                                        void *parserPtr,
                                        RaspRuleBase &rule) {
    auto *p = static_cast<Parser *>(parserPtr);

    if (key == "config") {
        if (!p->consume('{')) {
            return;
        }
        while (!p->peek('}') && p->ok()) {
            std::string ckey;
            if (!p->read_string(ckey) || !p->consume(':')) {
                break;
            }

            if (ckey == "regexField")
                p->read_string(rule.regexField);
            else if (ckey == "regexPatterns")
                p->read_string_array(rule.regexPatterns);
            else if (ckey == "regexChecks")
                p->read_regex_check_array(rule.regexChecks);
            else if (ckey == "regexCondition") {
                std::string cond;
                p->read_string(cond);
                rule.regexCondition = (cond == "all") ? RegexCondition::All : RegexCondition::Any;
            } else
                p->skip_value();

            p->consume(',');
        }
        p->consume('}');
    } else {
        // urlPatterns, methods, script, etc. — not used by AMSI sensor; skip.
        p->skip_value();
    }
}

// ── Module-scope RaspLog wrapper ──────────────────────────────────────────
// amsi_provider.cpp calls RaspLog as a free function.
// This thin wrapper forwards to the singleton's Log().
static void RaspLog(const char *fmt, ...) {
    char buf[1024];
    va_list va;
    va_start(va, fmt);
    vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);
    GetAmsiEngineRuntime().Log("%s", buf);
}

// =========================================================================
// ParseAndSwap — 接收从 rasp_sentry（守护进程）传来的 JSON 配置，解析并热替换当前内存中的安全策略
//
// Calls base ParseRulesJson() which allocates AmsiRaspRuleConfig objects via
// AllocRule() and populates all RaspRuleBase fields (id, sensor, enabled,
// mode, description, severity, scriptBodyBase64, scriptEval,
// scriptTimeoutInstructions). ParseRuleExtension() is not overridden —
// AMSI has no additional JSON fields beyond the base struct.
// =========================================================================

std::shared_ptr<const AmsiRuleEngine::RuleSnapshot> AmsiRuleEngine::BuildNextSnapshot(
        const std::string &json,
        const std::string &libSource,
        std::string &effectiveLib) {
    std::vector <std::unique_ptr<RaspRuleBase>> rawRules;
    std::string lib;
    if (!ParseRulesJson(json, lib, rawRules) || rawRules.empty()) {
        Log("[RaspAmsi] BuildNextSnapshot: no rules parsed");
        return {};
    }

    effectiveLib = lib.empty() ? libSource : lib;
    std::vector <AmsiRaspRuleConfig> configs;
    configs.reserve(rawRules.size());
    for (auto &ptr: rawRules) {
        auto *derived = static_cast<AmsiRaspRuleConfig *>(ptr.get());
        if (derived->sensor != "AmsiProvider")
            continue;
        configs.push_back(std::move(*derived));
    }

    PrecompileAll(configs, effectiveLib);
    return std::make_shared<RuleSnapshot>(RuleSnapshot{std::move(configs)});
}

void AmsiRuleEngine::PublishSnapshot(std::shared_ptr<const RuleSnapshot> next,
                                     const std::string &effectiveLib) {
    if (!next)
        return;

    std::atomic_store(&m_snapshot, next);
    m_libSource = effectiveLib;

    auto snap = std::atomic_load(&m_snapshot);
    Log("[RaspAmsi] ParseAndSwap: %zu AmsiProvider rule(s) loaded",
        snap ? snap->rules.size() : 0u);
}

bool AmsiRuleEngine::ParseAndSwap(const std::string &json, const std::string &libSource) {
    std::string nextEffectiveLib;
    auto next = BuildNextSnapshot(json, libSource, nextEffectiveLib);
    if (!next)
        return false;
    PublishSnapshot(next, nextEffectiveLib);
    return true;

#if 0
    std::vector <std::unique_ptr<RaspRuleBase>> rawRules;
    std::string lib;
    // 调用基类解析json
    if (!ParseRulesJson(json, lib, rawRules) || rawRules.empty()) {
        Log("[RaspAmsi] ParseAndSwap: no rules parsed");
        return false;
    }

    const std::string &effectiveLib = lib.empty() ? libSource : lib;
    // 遍历解析出的规则，精准剥离出只属于 AMSI 的规则，忽略其他规则
    std::vector <AmsiRaspRuleConfig> configs;
    configs.reserve(rawRules.size());
    for (auto &ptr: rawRules) {
        // Safe downcast: AllocRule() returned AmsiRaspRuleConfig
        auto *derived = static_cast<AmsiRaspRuleConfig *>(ptr.get());
        // Only keep AmsiProvider rules (sensor filter)
        if (derived->sensor != "AmsiProvider")
            continue;
        configs.push_back(std::move(*derived));
    }

    PrecompileAll(configs, effectiveLib);
    SwapRules(std::move(configs));  // 原子指针替换
    m_libSource = effectiveLib;

    auto snap = std::atomic_load(&m_snapshot);
    Log("[RaspAmsi] ParseAndSwap: %zu AmsiProvider rule(s) loaded",
        snap ? snap->rules.size() : 0u);
    return true;
#endif
}

/*
- **功能**：守护进程，处理配置重载信号（0x01）
- **重试策略**：最多3次，每次间隔1秒
- **成功条件**：ConnectSentry() && ParseAndSwap()
- **失败处理**：保留当前快照
*/
void AmsiRuleEngine::OnReloadSignal() {
    EngineRuntime& runtime = GetAmsiEngineRuntime();
    if (!runtime.CanAttemptReload()) {
        runtime.EmitTelemetry("reload_rejected", "state_not_reloadable");
        return;
    }

    bool buildOk = false;
    std::shared_ptr<const RuleSnapshot> next;
    std::string effectiveLib;
    for (int attempt = 0; attempt < 3 && !buildOk; attempt++) {
        if (attempt > 0)
            Sleep(1000);
        std::string json, lib;
        if (ConnectSentry(json, lib)) {
            next = BuildNextSnapshot(json, lib, effectiveLib);
            buildOk = (next != nullptr);
        }
    }

    if (!buildOk) {
        runtime.EmitTelemetry("reload_failed", "build_snapshot_failed");
        Log("[RaspAmsi] OnReloadSignal: sentry unavailable after 3 attempts - keeping snapshot");
        return;
    }

    auto guard = runtime.TryEnterReload("reload_signal");
    if (!guard.IsActive()) {
        runtime.EmitTelemetry("reload_rejected", "shutdown_or_state_changed");
        return;
    }

    PublishSnapshot(next, effectiveLib);
    guard.Complete(true, "published");
    return;

#if 0
    bool ok = false;
    for (int attempt = 0; attempt < 3 && !ok; attempt++) {
        if (attempt > 0)
            Sleep(1000);
        std::string json, lib;
        ok = false;
    }

    if (!ok)
        Log("[RaspAmsi] OnReloadSignal: sentry unavailable after 3 attempts — keeping snapshot");
#endif
}

/*
PrecompileAll / SwapRules
将 Base64 编码的 Lua 脚本源码与公共库 (libSource) 拼接后，交给 MoonSharp / Lua 虚拟机进行 JIT 或字节码编译
*/
void AmsiRuleEngine::PrecompileAll(const std::vector <AmsiRaspRuleConfig> &rules,
                                   const std::string &libSource) {
    m_luaEngine.Reset();

    for (const auto &rule: rules) {
        if (rule.scriptBodyBase64.empty())
            continue;

        std::string decoded;
        if (Base64Decode(rule.scriptBodyBase64, decoded)) {
            std::string combined = libSource.empty()
                                   ? decoded
                                   : libSource + "\n" + decoded;
            m_luaEngine.Precompile(rule.id, combined);
        } else {
            Log("[RaspAmsi] PrecompileAll: base64 decode failed rule=%s", rule.id.c_str());
        }
    }
}

// 原子交换规则快照
void AmsiRuleEngine::SwapRules(std::vector <AmsiRaspRuleConfig> &&rules) {
    std::shared_ptr<const RuleSnapshot> next =
            std::make_shared<RuleSnapshot>(RuleSnapshot{std::move(rules)});
    std::atomic_store(&m_snapshot, next);
}

// =========================================================================
// Self-unload support — triggered by IPC signal byte 0x02
//
// OnUnloadSignal() is called by ConfigPipeThread. It enters EngineRuntime's
// inert/shutdown path so new scans are rejected and in-flight scans drain with
// a bounded timeout. The DLL deliberately avoids self-unload from this path.
// =========================================================================

DWORD WINAPI AmsiRuleEngine::UnloadThreadProc(LPVOID)
{
    Sleep(200);

    EngineRuntime& runtime = GetAmsiEngineRuntime();
    runtime.Log("[RaspAmsi] UnloadThreadProc: entering inert mode and stopping background threads");
    runtime.BeginShutdown("unload_signal", 200);
    runtime.Log("[RaspAmsi] UnloadThreadProc: background threads stopped");

    char pid[12];
    char ackLine[192];
    sprintf_s(pid, sizeof(pid), "%lu", GetCurrentProcessId());
    snprintf(ackLine, sizeof(ackLine),
             "{\"cat\":\"drain-ack\",\"mod\":\"rasp_mod_amsi\",\"pid\":%s}", pid);

    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\rasp_sentry_events",
                               GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hPipe != INVALID_HANDLE_VALUE) {
        DWORD written = 0;
        WriteFile(hPipe, ackLine, static_cast<DWORD>(strlen(ackLine)), &written, nullptr);
        CloseHandle(hPipe);
    }

    return 0;
}

void AmsiRuleEngine::OnUnloadSignal() {
    Log("[RaspAmsi] OnUnloadSignal: unload requested - entering inert mode");

    HANDLE hThread = CreateThread(nullptr, 0, UnloadThreadProc, nullptr, 0, nullptr);
    if (hThread)
        CloseHandle(hThread);
    else
        Log("[RaspAmsi] OnUnloadSignal: failed to create unload thread - inert mode remains active");
}

// =========================================================================
// Evaluate (protected, implements RaspSentryBase pure virtual)
// 面向内部的 Evaluate (Protected 核心层)
// 规则调度与执行引擎 (Core Engine)。它不关心数据是从哪里来的（不管是 AMSI 还是其他的探针），它只负责拿着已经标准化好的上下文去匹配规则
// Iterates AmsiProvider rules; runs Lua for each; calls SendDetectionEvent()
// per match; returns all matched RaspEvalResults.
// ctx fields expected:
//   "contentName" — scanned item name (UTF-8)
//   "appName"     — calling host process (UTF-8)
//   "body"        — scanned bytes (binary-safe, isBinary=true)
// =========================================================================
std::vector <RaspEvalResult> AmsiRuleEngine::Evaluate(const std::string &sensor, const RaspLuaContext &ctx)
{
    std::vector <RaspEvalResult> results;

    auto snap = std::atomic_load(&m_snapshot);
    if (!snap)
        return results;

    // Extract context fields for result population
    std::string contentName;
    std::string appName;
    for (const auto &f: ctx.fields) {
        if (f.name == "contentName")
            contentName = f.value;
        else if (f.name == "appName")
            appName = f.value;
    }
    // 遍历每个规则
    for (const auto &rule: snap->rules) {
        if (!rule.enabled || rule.IsOff())
            continue;

        bool matched = false;
        std::string desc;
        std::string payload;

#ifdef RASP_PCRE2_AVAILABLE
        // 优先匹配正则表达式
        if (!rule.regexChecks.empty()) {
            // ── Multi-check gate (regexChecks) ─────────────────────────────
            // Evaluate each named check; collect IDs of checks that matched.
            std::vector<std::string> matchedIds;
            for (const auto &chk : rule.regexChecks) {
                const std::string *fp = nullptr;
                const std::string &want = chk.field.empty() ? std::string("body") : chk.field;
                for (const auto &f : ctx.fields)
                    if (f.name == want) {
                        fp = &f.value;
                        break;
                    }
                std::string mp;
                if (fp && !fp->empty() &&
                    m_luaEngine.MatchesAnyRegex(chk.patterns, *fp, mp))
                    matchedIds.push_back(chk.id);
            }
            bool gatePassed = (rule.regexCondition == RegexCondition::All)
                ? matchedIds.size() == rule.regexChecks.size()
                : !matchedIds.empty();
            if (!gatePassed)
                continue; // gate not satisfied — skip rule

            if (m_luaEngine.IsLoaded(rule.id))
            {
                // Gate passed → run Lua with matched IDs injected into context
                RaspLuaResult lr = m_luaEngine.Run(rule.id, sensor, ctx, rule.scriptTimeoutInstructions, matchedIds);
                if (lr.matched) {
                    matched = true;
                    desc    = lr.desc.empty() ? rule.description : lr.desc;
                    payload = lr.payload;
                }
            }
            else
            {
                // Gate passed, no script — fire directly; join matched IDs as payload
                matched = true;
                desc    = rule.description;
                for (size_t i = 0; i < matchedIds.size(); i++)
                {
                    if (i > 0) payload += ';';
                    payload += matchedIds[i];
                }
            }
        }
        else if (!rule.regexPatterns.empty())
        {
            // ── Legacy single-field regex check (no Lua required) ──────────
            const std::string *fieldPtr = nullptr;
            const std::string &wantField = rule.regexField.empty()
                                               ? std::string("body")
                                               : rule.regexField;
            for (const auto &f : ctx.fields)
                if (f.name == wantField) { fieldPtr = &f.value; break; }
            if (fieldPtr && !fieldPtr->empty())
            {
                std::string matchedPat;
                if (m_luaEngine.MatchesAnyRegex(rule.regexPatterns, *fieldPtr, matchedPat))
                {
                    matched = true;
                    desc    = rule.description;
                    payload = matchedPat;
                }
            }
        }
#endif // RASP_PCRE2_AVAILABLE

        // ── lua脚本check, PrecompileAll在这里预编译, 可以不走此部分 ─
        if (!matched && rule.regexChecks.empty() && m_luaEngine.IsLoaded(rule.id)) {
            RaspLuaResult lr = m_luaEngine.Run(rule.id, sensor, ctx,
                                               rule.scriptTimeoutInstructions);
            if (lr.matched) {
                matched = true;
                desc = lr.desc.empty() ? rule.description : lr.desc;
                payload = lr.payload;
            }
        } else if (!matched && rule.regexChecks.empty() &&
                   !m_luaEngine.IsLoaded(rule.id) && rule.regexPatterns.empty()) {
            Log("[RaspAmsi] Evaluate: rule=%s has no regexChecks, no Lua, and no regexPatterns — skipping",
                rule.id.c_str());
            continue;
        }
        // 正则和lua均匹配不到、放行
        if (!matched)
            continue;

        RaspEvalResult r;
        r.matched = true;
        r.block = rule.IsBlock();
        r.ruleId = rule.id;
        r.sensor = sensor;
        r.desc = desc;
        r.payload = payload;
        r.severity = rule.severity.empty() ? "High" : rule.severity;
        // url/method carry contentName/appName so SendDetectionEvent JSONL is complete
        r.contentName = contentName;
        r.appName = appName;
        if (rule.confidence) {
            r.confidence = rule.confidence;
        } else {
            r.confidence = DEFAULT_CONFIDENCE;
        }
        SendDetectionEvent(r);
        results.push_back(std::move(r));
        if (r.block) {
            break;  // 匹配到第一个阻断的才行
        }
    }

    return results;
}

/*
面向外部的 Evaluate (Public 接口层)
解析：面向 Windows 系统的“翻译官与接待员”
角色定位：边界适配器 (Adapter)。这是直接暴露给 IAntimalwareProvider::Scan（即 Windows AMSI COM 接口）的入口。
        Windows 系统不懂你的 C++ 内部对象，它只给你丢过来一堆原始的内存指针和字节长度
输入：接收 wchar_t*, char* 等原生指针参数
*/
AmsiEvalResult AmsiRuleEngine::Evaluate(
        const wchar_t *contentName,
        const wchar_t *appName,
        const char *sample,
        ULONG sampleLen) {
    AmsiEvalResult result;
    // windows宽字符转换为内部统一使用的utf-8字符串
    std::string contentNameUtf8 = WideToUtf8(contentName);
    std::string appNameUtf8 = WideToUtf8(appName);

    RaspLuaContext ctx;
    ctx.fields = {
            {"contentName", contentNameUtf8},
            {"appName",     appNameUtf8},
    };
    // true代表 isBinary
    if (sample && sampleLen > 0)
        ctx.fields.push_back({"body", std::string(sample, sampleLen), true});

    auto results = Evaluate("AmsiProvider", ctx);  // 调用真正的 Evaluate 函数
    if (!results.empty() && results[0].matched) {
        const auto &r = results[0];
        result.ruleMatched = true;
        result.block = r.block;
        result.ruleId = r.ruleId;
        result.desc = r.desc;
        result.payload = r.payload;
        result.severity = r.severity;
    }

    return result;
}
