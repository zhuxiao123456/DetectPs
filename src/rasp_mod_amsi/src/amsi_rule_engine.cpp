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
#include "../include/process_context_provider.h"
#include "../include/scan_context.h"
#include "rasp_scan_budget.h"

#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <cstring>
#include <string_view>
#define DEFAULT_CONFIDENCE 70

namespace {
    constexpr size_t kMaxScriptContentEventBytes = 8 * 1024;

    std::string TruncateForEventField(const std::string& value, size_t maxBytes)
    {
        if (value.size() <= maxBytes)
            return value;
        return value.substr(0, maxBytes);
    }


    uint32_t ParseUint32OrZero(const std::string& value)
    {
        try {
            return static_cast<uint32_t>(std::stoul(value));
        } catch (...) {
            return 0;
        }
    }

    std::string NormalizePathForContains(std::string_view value)
    {
        std::string normalized(value);
        std::replace(normalized.begin(), normalized.end(), '/', '\\');
        return normalized;
    }

    char LowerAscii(char ch)
    {
        return static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }

    bool ContainsIgnoreCase(std::string_view haystack, std::string_view needle)
    {
        if (needle.empty())
            return false;
        if (needle.size() > haystack.size())
            return false;

        return std::search(
                haystack.begin(),
                haystack.end(),
                needle.begin(),
                needle.end(),
                [](char lhs, char rhs) {
                    return LowerAscii(lhs) == LowerAscii(rhs);
                }) != haystack.end();
    }

    bool ContainsAnyIgnoreCaseNormalized(std::string_view normalizedHaystack,
                                         const std::vector<std::string>& needles)
    {
        for (const std::string& rawNeedle : needles) {
            if (rawNeedle.empty())
                continue;
            std::string needle = NormalizePathForContains(rawNeedle);
            if (ContainsIgnoreCase(normalizedHaystack, needle))
                return true;
        }
        return false;
    }

    std::string TrimAscii(std::string_view value)
    {
        size_t begin = 0;
        size_t end = value.size();
        while (begin < end && std::isspace(static_cast<unsigned char>(value[begin])))
            ++begin;
        while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1])))
            --end;
        return std::string(value.substr(begin, end - begin));
    }

    std::string NormalizeTrustedProcessPath(std::string_view value)
    {
        std::string normalized = TrimAscii(value);
        if (normalized.size() >= 2 && normalized.front() == '"' && normalized.back() == '"')
            normalized = normalized.substr(1, normalized.size() - 2);
        std::replace(normalized.begin(), normalized.end(), '/', '\\');
        while (normalized.size() > 3 && normalized.back() == '\\')
            normalized.pop_back();
        return normalized;
    }

    bool EqualsIgnoreCase(std::string_view lhs, std::string_view rhs)
    {
        return lhs.size() == rhs.size() &&
               std::equal(lhs.begin(), lhs.end(), rhs.begin(), [](char a, char b) {
                   return LowerAscii(a) == LowerAscii(b);
               });
    }

    bool EndsWithExeIgnoreCase(std::string_view value)
    {
        constexpr std::string_view suffix = ".exe";
        return value.size() >= suffix.size() &&
               EqualsIgnoreCase(value.substr(value.size() - suffix.size()), suffix);
    }

    bool IsAbsoluteWindowsExePath(std::string_view value)
    {
        return value.size() >= 7 &&
               std::isalpha(static_cast<unsigned char>(value[0])) &&
               value[1] == ':' &&
               value[2] == '\\' &&
               EndsWithExeIgnoreCase(value);
    }

    std::vector<std::string> NormalizeTrustProcessPaths(const std::vector<std::string>& paths)
    {
        std::vector<std::string> normalized;
        normalized.reserve(paths.size());
        for (const std::string& raw : paths) {
            const std::string path = NormalizeTrustedProcessPath(raw);
            if (!IsAbsoluteWindowsExePath(path))
                continue;
            normalized.push_back(path);
        }
        return normalized;
    }

    bool TrustProcessMatches(const std::vector<std::string>& trustedPaths,
                             const ScanContext* scanContext,
                             std::string* matchedTrustProcess)
    {
        if (trustedPaths.empty() || !scanContext || !scanContext->process)
            return false;
        const ProcessContextSnapshot& process = *scanContext->process;
        // The current AMSI detection surface is PowerShell-only, so trust_process
        // is scoped by the scan entry point and only needs to match the parent path.
        if (process.parentProcessPath.empty())
            return false;

        const std::string parentPath = NormalizeTrustedProcessPath(process.parentProcessPath);
        if (!IsAbsoluteWindowsExePath(parentPath))
            return false;

        for (const std::string& trustedPath : trustedPaths) {
            if (EqualsIgnoreCase(parentPath, trustedPath)) {
                if (matchedTrustProcess)
                    *matchedTrustProcess = trustedPath;
                return true;
            }
        }
        return false;
    }

    std::string JsonEscapeLocal(const std::string& value)
    {
        std::string out;
        out.reserve(value.size() + 8);
        for (unsigned char ch : value) {
            switch (ch) {
                case '\\': out += "\\\\"; break;
                case '"': out += "\\\""; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (ch < 0x20) {
                        char buf[7];
                        snprintf(buf, sizeof(buf), "\\u%04x", ch);
                        out += buf;
                    } else {
                        out += static_cast<char>(ch);
                    }
                    break;
            }
        }
        return out;
    }

    void SendTrustProcessSkipStatus(const ProcessContextSnapshot& process,
                                    const std::string& matchedTrustProcess)
    {
        char json[2048];
        _snprintf_s(json, sizeof(json), _TRUNCATE,
                    "{\"msgType\":\"TRUST_PROCESS_SKIP\","
                    "\"processPath\":\"%s\","
                    "\"parentProcessPath\":\"%s\","
                    "\"matchedTrustProcess\":\"%s\","
                    "\"reason\":\"trusted_parent_process\"}",
                    JsonEscapeLocal(process.currentProcessPath).c_str(),
                    JsonEscapeLocal(process.parentProcessPath).c_str(),
                    JsonEscapeLocal(matchedTrustProcess).c_str());

        HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\amsi_detect_control_status",
                                   GENERIC_WRITE, 0, nullptr,
                                   OPEN_EXISTING, 0, nullptr);
        if (hPipe == INVALID_HANDLE_VALUE)
            return;

        DWORD written = 0;
        const DWORD expected = static_cast<DWORD>(strlen(json));
        WriteFile(hPipe, json, expected, &written, nullptr);
        CloseHandle(hPipe);
    }

    bool ParentPathGatePasses(const AmsiRaspRuleConfig& rule, const ScanContext* scanContext)
    {
        const bool hasAllow = !rule.parentPathAllowContains.empty();
        const bool hasBlock = !rule.parentPathBlockContains.empty();
        if (!hasAllow && !hasBlock)
            return true;

        if (!scanContext || !scanContext->process || scanContext->process->parentProcessPath.empty())
            return false;

        const std::string parentPath = NormalizePathForContains(scanContext->process->parentProcessPath);
        if (ContainsAnyIgnoreCaseNormalized(parentPath, rule.parentPathAllowContains))
            return false;

        if (hasBlock)
            return ContainsAnyIgnoreCaseNormalized(parentPath, rule.parentPathBlockContains);

        return true;
    }

    thread_local const ScanContext* g_activeScanContext = nullptr;

    class ScopedScanContext {
    public:
        explicit ScopedScanContext(const ScanContext& scanContext)
                : previous_(g_activeScanContext)
        {
            g_activeScanContext = &scanContext;
        }

        ~ScopedScanContext()
        {
            g_activeScanContext = previous_;
        }

    private:
        const ScanContext* previous_;
    };

} // namespace
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
    auto& amsiRule = static_cast<AmsiRaspRuleConfig&>(rule);

    if (key == "parentPathAllowContains") {
        p->read_string_array(amsiRule.parentPathAllowContains);
    } else if (key == "parentPathBlockContains") {
        p->read_string_array(amsiRule.parentPathBlockContains);
    } else if (key == "config") {
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

static void RaspLogWithSeverity(RaspDiagSeverity severity, const char *fmt, ...) {
    char buf[1024];
    va_list va;
    va_start(va, fmt);
    vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);
    GetAmsiEngineRuntime().LogWithSeverity(severity, "%s", buf);
}

static void RaspLuaLog(const char* msg) {
    GetAmsiEngineRuntime().Log("%s", msg ? msg : "");
}

static void RaspLuaLogWithSeverity(RaspDiagSeverity severity, const char* msg) {
    GetAmsiEngineRuntime().LogWithSeverity(severity, "%s", msg ? msg : "");
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
    std::vector<std::string> rawTrustProcessPaths;
    RaspGlobalMode globalMode = RaspGlobalMode::Block;
    bool hasGlobalMode = false;
    uint32_t maxScanContentBytes = kDefaultMaxScanContentBytes;
    if (!ParseRulesJson(json,
                        lib,
                        rawRules,
                        nullptr,
                        &rawTrustProcessPaths,
                        &globalMode,
                        &hasGlobalMode,
                        &maxScanContentBytes) || rawRules.empty()) {
        LogWithSeverity(RaspDiagSeverity::Warning, "BuildNextSnapshot: no rules parsed");
        return {};
    }

    effectiveLib = lib.empty() ? libSource : lib;
    std::vector<std::string> trustProcessPaths = NormalizeTrustProcessPaths(rawTrustProcessPaths);
    std::vector <AmsiRaspRuleConfig> configs;
    configs.reserve(rawRules.size());
    for (auto &ptr: rawRules) {
        auto *derived = static_cast<AmsiRaspRuleConfig *>(ptr.get());
        if (derived->sensor != "AmsiProvider")
            continue;
        configs.push_back(std::move(*derived));
    }

    auto luaEngine = std::make_shared<RaspLuaEngine>();
    luaEngine->SetLogFn(RaspLuaLog);
    luaEngine->SetLeveledLogFn(RaspLuaLogWithSeverity);
    PrecompileAll(configs, effectiveLib, *luaEngine);
    return std::make_shared<RuleSnapshot>(
            RuleSnapshot{std::move(configs),
                         std::move(trustProcessPaths),
                         std::move(luaEngine),
                         hasGlobalMode,
                         globalMode,
                         maxScanContentBytes});
}

bool AmsiRuleEngine::ShouldBlockRule(const RuleSnapshot& snapshot,
                                     const RaspRuleBase& rule)
{
    if (rule.IsOff())
        return false;
    if (snapshot.hasGlobalMode && snapshot.globalMode == RaspGlobalMode::Audit)
        return false;
    return rule.IsBlock();
}

static const char* ResolveTimeoutDecision(const std::vector<RaspEvalResult>& results,
                                          ScanExecutionContext& exec)
{
    for (const auto& r : results) {
        if (r.block) {
            exec.decisionAfterTimeout = "block";
            return "block";
        }
    }
    if (!results.empty()) {
        exec.decisionAfterTimeout = "audit";
        return "audit";
    }
    exec.decisionAfterTimeout = "allow";
    return "allow";
}

static void EmitScanBudgetTelemetry(const ScanExecutionContext& exec)
{
    if (!exec.timedOut && !exec.regexLimitHit && !exec.regexSubjectTruncated)
        return;

    char msg[512];
    snprintf(msg, sizeof(msg),
             "[RaspAmsi][telemetry] scan_budget reason=%s decision=%s rules=%u regex_calls=%u lua_instr=%u regex_limit=%s subject_truncated=%d matched_before_timeout=%d\n",
             exec.timeoutReason.empty() ? "none" : exec.timeoutReason.c_str(),
             exec.decisionAfterTimeout.empty() ? "none" : exec.decisionAfterTimeout.c_str(),
             exec.rulesEvaluated,
             exec.regexCalls,
             exec.luaInstructions,
             exec.regexLimitType.empty() ? "none" : exec.regexLimitType.c_str(),
             exec.regexSubjectTruncated ? 1 : 0,
             exec.matchedBeforeTimeout ? 1 : 0);
    RaspLogWithSeverity(RaspDiagSeverity::Warning, "%s", msg);
}

void AmsiRuleEngine::PublishSnapshot(std::shared_ptr<const RuleSnapshot> next,
                                     const std::string &effectiveLib) {
    if (!next)
        return;

    std::atomic_store(&m_snapshot, next);
    m_libSource = effectiveLib;

    auto snap = std::atomic_load(&m_snapshot);
    LogWithSeverity(RaspDiagSeverity::Debug, "ParseAndSwap: %zu AmsiProvider rules loaded",
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
        Log("ParseAndSwap: no rules parsed");
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
    Log("ParseAndSwap: %zu AmsiProvider rule(s) loaded",
        snap ? snap->rules.size() : 0u);
    return true;
#endif
}

size_t AmsiRuleEngine::ActiveRuleCountForStatus() const {
    auto snap = std::atomic_load(&m_snapshot);
    return snap ? snap->rules.size() : 0u;
}

/*
- **功能**：守护进程，处理配置重载信号（0x01）
- **重试策略**：最多3次，每次间隔1秒
- **成功条件**：ConnectSentry() && ParseAndSwap()
- **失败处理**：保留当前快照
*/
void AmsiRuleEngine::OnReloadSignal() {
    EngineRuntime& runtime = GetAmsiEngineRuntime();
    const bool waitResumeAfterHostLost = IsWaitingResumeAfterHostLost();
    runtime.PauseDetection();
    MarkDetectionPausedByHostState(true);
    MarkRuleSnapshotReady(false);
    if (!runtime.CanAttemptReload()) {
        runtime.EmitTelemetry("reload_rejected", "state_not_reloadable");
        MarkWaitingResumeAfterHostLost(true);
        SendRuleLoadResult(false, 4, "reload rejected: state not reloadable");
        return;
    }

    bool buildOk = false;
    bool connectedOnce = false;
    RuleBundleMetadata requestedMetadata;
    std::string requestedEffectiveHash;
    std::shared_ptr<const RuleSnapshot> next;
    std::string effectiveLib;
    for (int attempt = 0; attempt < 3 && !buildOk; attempt++) {
        if (attempt > 0)
            Sleep(1000);
        std::string json, lib;
        RuleBundleMetadata attemptMetadata;
        if (ConnectSentry(json, lib, attemptMetadata)) {
            connectedOnce = true;
            const std::string attemptEffectiveHash = ComputeEffectiveSnapshotHash(json);
            next = BuildNextSnapshot(json, lib, effectiveLib);
            buildOk = (next != nullptr);
            if (buildOk) {
                requestedMetadata = attemptMetadata;
                requestedEffectiveHash = attemptEffectiveHash;
            } else {
                requestedMetadata = attemptMetadata;
            }
        }
    }

    if (!buildOk) {
        runtime.EmitTelemetry("reload_failed", "build_snapshot_failed");
        SendRuleLoadResult(false,
                           connectedOnce ? 3 : 1,
                           connectedOnce ? "reload build snapshot failed" : "reload rules pipe unavailable",
                           requestedMetadata);
        MarkHostAlive(false);
        MarkRuleSnapshotReady(false);
        MarkDetectionPausedByHostState(true);
        MarkWaitingResumeAfterHostLost(true);
        LogWithSeverity(RaspDiagSeverity::Warning,
                        "Reload failed, AMSI detection remains paused");
        return;
    }

    auto guard = runtime.TryEnterReload("reload_signal");
    if (!guard.IsActive()) {
        runtime.EmitTelemetry("reload_rejected", "shutdown_or_state_changed");
        MarkWaitingResumeAfterHostLost(true);
        SendRuleLoadResult(false, 4, "reload rejected: shutdown or state changed", requestedMetadata);
        return;
    }

    PublishSnapshot(next, effectiveLib);
    SetActiveRuleMetadataForStatus(requestedMetadata);
    SetActiveEffectiveSnapshotHash(requestedEffectiveHash);
    MarkHostAlive(true);
    MarkRuleSnapshotReady(true);
    if (waitResumeAfterHostLost) {
        MarkDetectionPausedByHostState(false);
        MarkWaitingResumeAfterHostLost(false);
        runtime.ResumeDetection();
        guard.Complete(true, "published_recovered_after_host_lost");
        SendRuleLoadResult(true, 0, "", requestedMetadata);
        LogWithSeverity(RaspDiagSeverity::Info, "Reload succeeded after host lost - detection resumed");
        return;
    }

    MarkDetectionPausedByHostState(false);
    MarkWaitingResumeAfterHostLost(false);
    runtime.ResumeDetection();
    guard.Complete(true, "published_running");
    LogWithSeverity(RaspDiagSeverity::Info, "Reload succeeded - detection resumed");
    SendRuleLoadResult(true, 0, "", requestedMetadata);
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
        Log("OnReloadSignal: sentry unavailable after 3 attempts — keeping snapshot");
#endif
}

/*
PrecompileAll / SwapRules
将 Base64 编码的 Lua 脚本源码与公共库 (libSource) 拼接后，交给 MoonSharp / Lua 虚拟机进行 JIT 或字节码编译
*/
void AmsiRuleEngine::PrecompileAll(const std::vector <AmsiRaspRuleConfig> &rules,
                                   const std::string &libSource,
                                   RaspLuaEngine& luaEngine) {
    for (const auto &rule: rules) {
        if (rule.scriptBodyBase64.empty())
            continue;

        std::string decoded;
        if (Base64Decode(rule.scriptBodyBase64, decoded)) {
            const bool isBytecode = (rule.scriptEncoding == "bytecode");
            if (isBytecode) {
                LogWithSeverity(RaspDiagSeverity::Debug, "PrecompileAll: rule=%s scriptEncoding=bytecode accepted",
                                rule.id.c_str());
                luaEngine.Precompile(rule.id, decoded, true);
                continue;
            }

            if (!rule.scriptEncoding.empty() && rule.scriptEncoding != "source") {
                LogWithSeverity(RaspDiagSeverity::Warning, "PrecompileAll: unknown scriptEncoding=%s rule=%s, treating as source",
                                rule.scriptEncoding.c_str(), rule.id.c_str());
            }

            std::string combined = libSource.empty()
                                   ? decoded
                                   : libSource + "\n" + decoded;
            luaEngine.Precompile(rule.id, combined, false);
        } else {
            LogWithSeverity(RaspDiagSeverity::Warning, "PrecompileAll: base64 decode failed rule=%s", rule.id.c_str());
        }
    }
}

// 原子交换规则快照
void AmsiRuleEngine::SwapRules(std::vector <AmsiRaspRuleConfig> &&rules) {
    std::shared_ptr<const RuleSnapshot> next =
            std::make_shared<RuleSnapshot>(
                    RuleSnapshot{std::move(rules),
                                 {},
                                 std::make_shared<RaspLuaEngine>(),
                                 false,
                                 RaspGlobalMode::Block,
                                 kDefaultMaxScanContentBytes});
    std::atomic_store(&m_snapshot, next);
}

void AmsiRuleEngine::FillDiagnosticLogContext(LegacyDiagJsonBuildInput& input) const
{
    const ProcessContextSnapshot& process = GetProcessContextProvider().GetSnapshot();

    input.pid = process.currentPid != 0 ? process.currentPid : GetCurrentProcessId();
    char pidText[16] = {};
    sprintf_s(pidText, sizeof(pidText), "%lu", static_cast<unsigned long>(input.pid));
    input.dllInstanceId = std::string("amsi_detect_") + pidText;

    input.processName = process.currentProcessName;
    input.processPath = process.currentProcessPath;
    input.parentPid = process.parentPid;
    input.parentProcessName = process.parentProcessName;
    input.parentProcessPath = process.parentProcessPath;
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
        runtime.LogWithSeverity(RaspDiagSeverity::Info, "UnloadThreadProc: entering inert mode and stopping background threads");
        runtime.BeginShutdown("unload_signal", 200);
        runtime.LogWithSeverity(RaspDiagSeverity::Info, "UnloadThreadProc: background threads stopped");

        char pid[12];
        char ackLine[192];
        sprintf_s(pid, sizeof(pid), "%lu", GetCurrentProcessId());
        snprintf(ackLine, sizeof(ackLine),
        "{\"cat\":\"drain-ack\",\"mod\":\"hss_amsi\",\"pid\":%s}", pid);

        HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\amsi_detect_events",
        GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hPipe != INVALID_HANDLE_VALUE) {
            DWORD written = 0;
            WriteFile(hPipe, ackLine, static_cast<DWORD>(strlen(ackLine)), &written, nullptr);
            CloseHandle(hPipe);
        }

        return 0;
        }

void AmsiRuleEngine::OnUnloadSignal() {
    HANDLE hThread = CreateThread(nullptr, 0, UnloadThreadProc, nullptr, 0, nullptr);
    if (hThread)
        CloseHandle(hThread);
    else
        LogWithSeverity(RaspDiagSeverity::Error, "OnUnloadSignal: failed to create unload thread - inert mode remains active");
}

void AmsiRuleEngine::OnPauseDetectionSignal()
{
    MarkDetectionPausedByHostState(true);
    GetAmsiEngineRuntime().PauseDetection();
}

void AmsiRuleEngine::OnResumeDetectionSignal()
{
    if (!IsHostAlive()) {
        MarkWaitingResumeAfterHostLost(true);
        LogWithSeverity(RaspDiagSeverity::Warning,
                        "Resume ignored because host is not alive");
        return;
    }
    if (!IsRuleSnapshotReady()) {
        MarkWaitingResumeAfterHostLost(true);
        LogWithSeverity(RaspDiagSeverity::Warning,
                        "Resume ignored because rule snapshot is not ready");
        return;
    }

    MarkDetectionPausedByHostState(false);
    MarkWaitingResumeAfterHostLost(false);
    GetAmsiEngineRuntime().ResumeDetection();
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
std::vector<RaspEvalResult> AmsiRuleEngine::Evaluate(const std::string& sensor,
                                                     const RaspLuaContext& ctx)
{
    return EvaluateWithScanContext(sensor, ctx, g_activeScanContext);
}

std::vector <RaspEvalResult> AmsiRuleEngine::EvaluateWithScanContext(
        const std::string &sensor,
        const RaspLuaContext &ctx,
        const ScanContext* scanContext)
{
    std::vector <RaspEvalResult> results;
    ScanExecutionContext exec;

    auto snap = std::atomic_load(&m_snapshot);
    if (!snap || !snap->luaEngine)
        return results;
    RaspLuaEngine& luaEngine = *snap->luaEngine;

    // Batch 3: 一次性提取 parent 字段
    uint32_t parentPid = 0;
    std::string parentProcessName;
    std::string parentProcessPath;
    uint32_t processPid = 0;
    std::string processName;
    std::string processPath;
    std::string scriptContent;
    for (const auto &f: ctx.fields) {
        if (f.name == "parentPid") {
            parentPid = ParseUint32OrZero(f.value);
        } else if (f.name == "parentProcessName") {
            parentProcessName = f.value;
        } else if (f.name == "parentProcessPath") {
            parentProcessPath = f.value;
        } else if (f.name == "processPid") {
            processPid = ParseUint32OrZero(f.value);
        } else if (f.name == "processName") {
            processName = f.value;
        } else if (f.name == "processPath") {
            processPath = f.value;
        } else if (f.name == "script_content") {
            scriptContent = f.value;
        }
    }

    // Extract context fields for result population
    std::string contentName;
    std::string appName;
    for (const auto &f: ctx.fields) {
        if (f.name == "contentName")
            contentName = f.value;
        else if (f.name == "appName")
            appName = f.value;
    }

    std::string matchedTrustProcess;
    if (TrustProcessMatches(snap->trustProcessPaths, scanContext, &matchedTrustProcess)) {
        SendTrustProcessSkipStatus(*scanContext->process, matchedTrustProcess);
        LogWithSeverity(RaspDiagSeverity::Debug, "trust_process skip: parentProcessPath=%s matched=%s",
                        scanContext->process->parentProcessPath.c_str(),
                        matchedTrustProcess.c_str());
        return results;
    }
    // 遍历每个规则
    for (const auto &rule: snap->rules) {
        if (!exec.TryEnterRule())
            break;

        if (!rule.enabled || rule.IsOff())
            continue;

        // Parent path gate is rule-local: skip only this rule and keep
        // evaluating later rules in the same scan.
        if (!ParentPathGatePasses(rule, scanContext))
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
                    luaEngine.MatchesAnyRegex(chk.patterns, *fp, mp, &exec))
                    matchedIds.push_back(chk.id);
                if (exec.timedOut)
                    break;
            }
            if (exec.timedOut)
                break;
            bool gatePassed = (rule.regexCondition == RegexCondition::All)
                ? matchedIds.size() == rule.regexChecks.size()
                : !matchedIds.empty();
            if (!gatePassed)
                continue; // gate not satisfied — skip rule

            if (luaEngine.IsLoaded(rule.id))
            {
                // Gate passed → run Lua with matched IDs injected into context
                RaspLuaResult lr = luaEngine.Run(rule.id, sensor, ctx, rule.scriptTimeoutInstructions, matchedIds, &exec);
                if (lr.timedOut)
                    break;
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
                if (luaEngine.MatchesAnyRegex(rule.regexPatterns, *fieldPtr, matchedPat, &exec))
                {
                    matched = true;
                    desc    = rule.description;
                    payload = matchedPat;
                }
                if (exec.timedOut)
                    break;
            }
        }
#endif // RASP_PCRE2_AVAILABLE

        // ── lua脚本check, PrecompileAll在这里预编译, 可以不走此部分 ─
        if (!matched && rule.regexChecks.empty() && luaEngine.IsLoaded(rule.id)) {
            RaspLuaResult lr = luaEngine.Run(rule.id, sensor, ctx,
                                             rule.scriptTimeoutInstructions,
                                             {},
                                             &exec);
            if (lr.timedOut)
                break;
            if (lr.matched) {
                matched = true;
                desc = lr.desc.empty() ? rule.description : lr.desc;
                payload = lr.payload;
            }
        } else if (!matched && rule.regexChecks.empty() &&
                   !luaEngine.IsLoaded(rule.id) && rule.regexPatterns.empty()) {
            LogWithSeverity(RaspDiagSeverity::Warning, "Evaluate: rule=%s has no regexChecks, no Lua, and no regexPatterns — skipping",
                            rule.id.c_str());
            continue;
        }
        // 正则和lua均匹配不到、放行
        if (!matched)
            continue;

        RaspEvalResult r;
        r.matched = true;
        r.block = ShouldBlockRule(*snap, rule);
        r.ruleId = rule.id;
        r.sensor = sensor;
        r.desc = desc;
        r.payload = payload;
        r.severity = rule.severity.empty() ? "High" : rule.severity;
        // url/method carry contentName/appName so SendDetectionEvent JSONL is complete
        r.contentName = contentName;
        r.appName = appName;
        r.processPid = processPid;
        r.processName = processName;
        r.processPath = processPath;
        r.scriptContent = scriptContent;
        // Batch 3: parent process fields
        r.parentPid = parentPid;
        r.parentProcessName = parentProcessName;
        r.parentProcessPath = parentProcessPath;
        if (rule.confidence) {
            r.confidence = rule.confidence;
        } else {
            r.confidence = DEFAULT_CONFIDENCE;
        }
        TrySubmitDetectionEvent(r);
        exec.matchedBeforeTimeout = true;
        const bool shouldBlock = r.block;
        results.push_back(std::move(r));
        if (shouldBlock) {
            break;  // 匹配到第一个阻断的才行
        }
    }

    if (exec.timedOut)
        ResolveTimeoutDecision(results, exec);
    EmitScanBudgetTelemetry(exec);
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
    ScanContext scanContext;
    return Evaluate(contentName, appName, sample, sampleLen, scanContext);
}

AmsiEvalResult AmsiRuleEngine::Evaluate(
        const wchar_t *contentName,
        const wchar_t *appName,
        const char *sample,
        ULONG sampleLen,
        const ScanContext& scanContext) {
    AmsiEvalResult result;
    ScopedScanContext scopedScanContext(scanContext);
    // windows宽字符转换为内部统一使用的utf-8字符串
    std::string contentNameUtf8 = WideToUtf8(contentName);
    std::string appNameUtf8 = WideToUtf8(appName);

    RaspLuaContext ctx;
    ctx.fields = {
            {"contentName", contentNameUtf8},
            {"appName",     appNameUtf8},
    };
    if (scanContext.process) {
        const ProcessContextSnapshot& process = *scanContext.process;
        ctx.fields.push_back({"processPid", std::to_string(process.currentPid)});
        ctx.fields.push_back({"processName", process.currentProcessName});
        ctx.fields.push_back({"processPath", process.currentProcessPath});

        ctx.fields.push_back({"parentPid", std::to_string(process.parentPid)});
        ctx.fields.push_back({"parentProcessName", process.parentProcessName});
        ctx.fields.push_back({"parentProcessPath", process.parentProcessPath});
        ctx.fields.push_back({"processCaptureStatus", ProcessCaptureStatusToString(process.status)});
        ctx.fields.push_back({"processRetryState", ProcessRetryStateToString(process.retryState)});
    }
    auto snap = std::atomic_load(&m_snapshot);
    const size_t maxScanContentBytes = snap
        ? snap->maxScanContentBytes
        : kDefaultMaxScanContentBytes;

    // true代表 isBinary
    NormalizedScriptInput normalized = m_inputNormalizer.Normalize(
        sample,
        sampleLen,
        maxScanContentBytes);
    if (!normalized.normalized.empty()) {
        ctx.fields.push_back({"body", normalized.normalized, true});
        ctx.fields.push_back({"script_content", TruncateForEventField(normalized.normalized, kMaxScriptContentEventBytes)});
        LogWithSeverity(RaspDiagSeverity::Debug,
                        "normalizer rawLen=%zu normalizedLen=%zu maxScanContentBytes=%zu truncated=%d utf16=%d b64=%d nulls=%d",
                        normalized.rawLen,
                        normalized.normalizedLen,
                        maxScanContentBytes,
                        normalized.truncated ? 1 : 0,
                        normalized.decodedUtf16Le ? 1 : 0,
                        normalized.decodedBase64 ? 1 : 0,
                        normalized.hadNullBytes ? 1 : 0);
    }

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