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

    const char* ScanContextAppendSkipReasonToString(ScanContextAppendSkipReason reason)
    {
        switch (reason) {
            case ScanContextAppendSkipReason::None:
                return "none";
            case ScanContextAppendSkipReason::ContentNameInfrastructure:
                return "content_name_infrastructure";
            case ScanContextAppendSkipReason::BodyPrefixInfrastructure:
                return "body_prefix_infrastructure";
            case ScanContextAppendSkipReason::TooLarge:
                return "too_large";
            case ScanContextAppendSkipReason::EmptyBody:
                return "empty_body";
            case ScanContextAppendSkipReason::Disabled:
                return "disabled";
            case ScanContextAppendSkipReason::RateLimited:
                return "rate_limited";
            case ScanContextAppendSkipReason::GlobalTimeout:
                return "global_timeout";
            case ScanContextAppendSkipReason::Exception:
                return "exception";
            default:
                return "unknown";
        }
    }

    bool ContentNameLooksLikeInfrastructure(std::string_view contentName)
    {
        if (contentName.empty())
            return false;
        static constexpr const char* kInfrastructureNames[] = {
            ".psm1",
            ".psd1",
            ".ps1xml",
            "psreadline.psm1",
            "microsoft.powershell.utility.psm1"
        };
        for (const char* pattern : kInfrastructureNames) {
            if (ContainsIgnoreCase(contentName, pattern))
                return true;
        }
        return false;
    }

    bool BodyPrefixLooksLikeInfrastructure(std::string_view body, uint32_t prefixFilterBytes)
    {
        if (body.empty() || prefixFilterBytes == 0)
            return false;
        const size_t limit = (std::min)(body.size(), static_cast<size_t>(prefixFilterBytes));
        const std::string_view prefix(body.data(), limit);
        static constexpr const char* kInfrastructurePrefixes[] = {
            "ModuleVersion",
            "GUID",
            "RootModule",
            "NestedModules",
            "FunctionsToExport",
            "CmdletsToExport",
            "AliasesToExport",
            "HelpInfoURI",
            "CompanyName",
            "Copyright",
            "function prompt",
            "$NestedPromptLevel",
            "$host.UI.RawUI",
            "PSConsoleHostReadline",
            "[System.Diagnostics.DebuggerHidden()]",
            "FullyQualifiedErrorId",
            "InvocationInfo",
            "PositionMessage",
            "PSMessageDetails",
            "ErrorCategory_Message",
            "CategoryInfo",
            "http://go.microsoft.com/fwlink/",
            "PS $($executionContext.SessionState.Path.CurrentLocation)",
            "Set-StrictMode -Version 1",
            "OriginInfo"
        };
        for (const char* pattern : kInfrastructurePrefixes) {
            if (ContainsIgnoreCase(prefix, pattern))
                return true;
        }
        return false;
    }
    void TrimStringTailInPlace(std::string& value, size_t maxBytes)
    {
        if (maxBytes == 0) {
            value.clear();
            return;
        }
        if (value.size() > maxBytes)
            value.erase(0, value.size() - maxBytes);
    }

    std::string TrimStringTail(std::string value, size_t maxBytes)
    {
        TrimStringTailInPlace(value, maxBytes);
        return value;
    }
    std::string EscapeForScanContentDump(const std::string& value, size_t maxBytes)
    {
        const size_t limit = (std::min)(value.size(), maxBytes);
        std::string out;
        out.reserve(limit + limit / 8 + 64);
        char hex[8] = {};
        for (size_t i = 0; i < limit; ++i) {
            const unsigned char ch = static_cast<unsigned char>(value[i]);
            switch (ch) {
                case '\r': out += "\\r"; break;
                case '\n': out += "\\n"; break;
                case '\t': out += "\\t"; break;
                case '\\': out += "\\\\"; break;
                case 0: out += "\\0"; break;
                default:
                    if (ch < 0x20 || ch == 0x7f) {
                        std::snprintf(hex, sizeof(hex), "\\x%02X", static_cast<unsigned int>(ch));
                        out += hex;
                    } else {
                        out.push_back(static_cast<char>(ch));
                    }
                    break;
            }
        }
        if (value.size() > maxBytes) {
            out += "\\n...[truncated bytes=";
            out += std::to_string(value.size() - maxBytes);
            out += "]";
        }
        return out;
    }

    struct ScanContentDebugDumpInfo {
        bool enabled = false;
        bool appendAllowed = false;
        ScanContextAppendSkipReason appendSkipReason = ScanContextAppendSkipReason::Disabled;
        size_t currentLen = 0;
        size_t bufferedLen = 0;
        size_t evalLen = 0;
        bool expired = false;
        std::string snapshotHash;
    };

    void WriteScanContentDebugDump(const ProcessContextSnapshot* process,
                                   const std::string& contentName,
                                   const std::string& appName,
                                   const ScanContentDebugDumpInfo& buildInfo,
                                   const std::string& currentBody,
                                   const std::string& evalBody,
                                   uint32_t maxDumpBytes)
    {
        if (maxDumpBytes == 0)
            return;

        std::string out;
        out.reserve((std::min)(currentBody.size(), static_cast<size_t>(maxDumpBytes)) +
                    (std::min)(evalBody.size(), static_cast<size_t>(maxDumpBytes)) + 1024);
        out += "[RaspAmsi][scan_dump] ";
        out += "tickMs=" + std::to_string(GetTickCount64());
        out += " pid=" + std::to_string(GetCurrentProcessId());
        out += " tid=" + std::to_string(GetCurrentThreadId());
        out += " contentName=" + EscapeForScanContentDump(contentName, 1024);
        out += " appName=" + EscapeForScanContentDump(appName, 512);
        if (process) {
            out += " processPid=" + std::to_string(process->currentPid);
            out += " processName=" + process->currentProcessName;
            out += " processPath=" + process->currentProcessPath;
            out += " parentPid=" + std::to_string(process->parentPid);
            out += " parentProcessName=" + process->parentProcessName;
            out += " parentProcessPath=" + process->parentProcessPath;
        }
        out += " scanContextEnabled=" + std::to_string(buildInfo.enabled ? 1 : 0);
        out += " expired=" + std::to_string(buildInfo.expired ? 1 : 0);
        out += " appendAllowed=" + std::to_string(buildInfo.appendAllowed ? 1 : 0);
        out += " appendSkipReason=" + std::string(ScanContextAppendSkipReasonToString(buildInfo.appendSkipReason));
        out += " currentLen=" + std::to_string(buildInfo.currentLen);
        out += " bufferedLen=" + std::to_string(buildInfo.bufferedLen);
        out += " evalLen=" + std::to_string(buildInfo.evalLen);
        if (!buildInfo.snapshotHash.empty()) {
            out += " snapshotHash=" + buildInfo.snapshotHash;
        }
        out += " currentBody=\"";
        out += EscapeForScanContentDump(currentBody, maxDumpBytes);
        out += "\" evalBody=\"";
        out += EscapeForScanContentDump(evalBody, maxDumpBytes);
        out += "\"";

        GetAmsiEngineRuntime().LogWithSeverity(RaspDiagSeverity::Debug, "%s", out.c_str());
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

    bool WriteDrainAckWithTimeout(const char* ackLine, DWORD timeoutMs)
    {
        HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\amsi_detect_events",
                                   GENERIC_WRITE, 0, nullptr,
                                   OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
        if (hPipe == INVALID_HANDLE_VALUE)
            return false;

        OVERLAPPED ov = {};
        ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        if (!ov.hEvent) {
            CloseHandle(hPipe);
            return false;
        }

        DWORD written = 0;
        const DWORD expected = static_cast<DWORD>(strlen(ackLine));
        BOOL ok = WriteFile(hPipe, ackLine, expected, nullptr, &ov);
        DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        if (!ok && error == ERROR_IO_PENDING) {
            DWORD wait = WaitForSingleObject(ov.hEvent, timeoutMs);
            if (wait == WAIT_OBJECT_0) {
                ok = GetOverlappedResult(hPipe, &ov, &written, TRUE);
            } else {
                CancelIo(hPipe);
                GetOverlappedResult(hPipe, &ov, &written, TRUE);
                SetLastError(ERROR_TIMEOUT);
                ok = FALSE;
            }
        } else if (ok) {
            ok = GetOverlappedResult(hPipe, &ov, &written, TRUE);
        }

        CloseHandle(ov.hEvent);
        CloseHandle(hPipe);
        return ok == TRUE && written == expected;
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
    constexpr size_t kMaxAmsiMetadataChars = 4096;
    size_t boundedLen = 0;
    while (boundedLen < kMaxAmsiMetadataChars && w[boundedLen] != L'\0')
        ++boundedLen;
    if (boundedLen == 0)
        return {};

    int inputLen = static_cast<int>(boundedLen);
    int len = WideCharToMultiByte(CP_UTF8, 0, w, inputLen, nullptr, 0, nullptr, nullptr);
    if (len <= 0)
        return {};
    std::string s(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, inputLen, &s[0], len, nullptr, nullptr);
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
    uint32_t totalScanTimeoutMs = kDefaultTotalScanTimeoutMs;
    uint32_t maxRulesPerScan = kDefaultMaxRulesPerScan;
    uint32_t maxRegexCallsPerScan = kDefaultMaxRegexCallsPerScan;
    uint32_t auditMaxEventsPerScan = kDefaultAuditMaxEventsPerScan;
    bool stopAfterFirstBlock = true;
    ScanRateLimitConfig scanRateLimit;
    ScanContextConfig scanContext;
    DiagnosticsConfig diagnostics;
    const std::string effectiveHash = ComputeEffectiveSnapshotHash(json);
    if (!ParseRulesJson(json,
                        lib,
                        rawRules,
                        nullptr,
                        &rawTrustProcessPaths,
                        &globalMode,
                        &hasGlobalMode,
                        &maxScanContentBytes,
                        &auditMaxEventsPerScan,
                        &stopAfterFirstBlock,
                        &totalScanTimeoutMs,
                        &maxRulesPerScan,
                        &maxRegexCallsPerScan,
                        &scanRateLimit,
                         nullptr,
                         &scanContext,
                         nullptr,
                         &diagnostics,
                         nullptr) || rawRules.empty()) {
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

    std::vector<size_t> blockRuleIndexes;
    std::vector<size_t> alertRuleIndexes;
    blockRuleIndexes.reserve(configs.size());
    alertRuleIndexes.reserve(configs.size());
    for (size_t i = 0; i < configs.size(); ++i) {
        if (configs[i].IsBlock()) {
            blockRuleIndexes.push_back(i);
        } else {
            alertRuleIndexes.push_back(i);
        }
    }

    auto luaEngine = std::make_shared<RaspLuaEngine>();
    luaEngine->SetLogFn(RaspLuaLog);
    luaEngine->SetLeveledLogFn(RaspLuaLogWithSeverity);
    PrecompileAll(configs, effectiveLib, *luaEngine);
    return std::make_shared<RuleSnapshot>(
            RuleSnapshot{std::move(configs),
                         std::move(blockRuleIndexes),
                         std::move(alertRuleIndexes),
                         std::move(trustProcessPaths),
                         std::move(luaEngine),
                          hasGlobalMode,
                           globalMode,
                           maxScanContentBytes,
                           totalScanTimeoutMs,
                           maxRulesPerScan,
                           maxRegexCallsPerScan,
                           auditMaxEventsPerScan,
                           stopAfterFirstBlock,
                           scanRateLimit,
                           scanContext,
                           diagnostics,
                           effectiveHash});
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

AmsiRuleEngine::ScanRateLimitDecision AmsiRuleEngine::ShouldBypassByScanRateLimit(
        const ScanRateLimitConfig& config,
        uint64_t nowMs)
{
    ScanRateLimitDecision decision;
    decision.enabled = config.enabled;
    if (!config.enabled)
        return decision;

    const uint32_t bypassPermille =
        static_cast<uint32_t>(config.bypassRatioAfterLimit * 1000.0 + 0.5);
    decision.bypassPermille = bypassPermille;

    std::lock_guard<std::mutex> lock(m_rateLimitMutex);
    if (m_rateLimitWindowStartMs == 0 ||
        nowMs < m_rateLimitWindowStartMs ||
        nowMs - m_rateLimitWindowStartMs >= config.windowMs) {
        if (m_rateLimitWindowLimitEntered) {
            LogWithSeverity(RaspDiagSeverity::Warning,
                            "AMSI scan rate limit summary: scans=%llu bypassed=%u evaluatedAfterLimit=%u windowMs=%u maxScans=%u",
                            static_cast<unsigned long long>(m_rateLimitWindowScanCount),
                            m_rateLimitWindowBypassed,
                            m_rateLimitWindowEvaluatedAfterLimit,
                            config.windowMs,
                            config.maxScans);
        }
        m_rateLimitWindowStartMs = nowMs;
        m_rateLimitWindowScanCount = 0;
        m_rateLimitOverLimitSeq = 0;
        m_rateLimitWindowBypassed = 0;
        m_rateLimitWindowEvaluatedAfterLimit = 0;
        m_rateLimitWindowLimitEntered = false;
    }

    ++m_rateLimitWindowScanCount;
    decision.windowScanCount = m_rateLimitWindowScanCount;
    if (m_rateLimitWindowScanCount <= config.maxScans)
        return decision;

    decision.overLimit = true;
    decision.reason = "scan_rate_limited";
    decision.overLimitSeq = ++m_rateLimitOverLimitSeq;

    if (!m_rateLimitWindowLimitEntered) {
        LogWithSeverity(RaspDiagSeverity::Warning,
                        "AMSI scan rate limit entered: windowMs=%u maxScans=%u bypassRatio=%.2f",
                        config.windowMs,
                        config.maxScans,
                        config.bypassRatioAfterLimit);
        m_rateLimitWindowLimitEntered = true;
    }

    decision.bypass = ((decision.overLimitSeq * 9973ULL) % 1000ULL) < bypassPermille;
    if (decision.bypass) {
        ++m_rateLimitWindowBypassed;
    } else {
        ++m_rateLimitWindowEvaluatedAfterLimit;
    }
    return decision;
}

ScanContextAppendDecision AmsiRuleEngine::ShouldAppendToScanContext(
        const std::string& contentName,
        const std::string& currentContent,
        const ScanContextConfig& config) const
{
    ScanContextAppendDecision decision;
    if (!config.enabled || config.maxBufferedBytes == 0) {
        decision.reason = ScanContextAppendSkipReason::Disabled;
        return decision;
    }
    if (currentContent.empty()) {
        decision.reason = ScanContextAppendSkipReason::EmptyBody;
        return decision;
    }
    if (ContentNameLooksLikeInfrastructure(contentName)) {
        decision.reason = ScanContextAppendSkipReason::ContentNameInfrastructure;
        return decision;
    }
    if (BodyPrefixLooksLikeInfrastructure(currentContent, config.prefixFilterBytes)) {
        decision.reason = ScanContextAppendSkipReason::BodyPrefixInfrastructure;
        return decision;
    }
    if (currentContent.size() > config.maxAppendBytes) {
        decision.reason = ScanContextAppendSkipReason::TooLarge;
        return decision;
    }

    decision.reason = ScanContextAppendSkipReason::None;
    return decision;
}

std::string AmsiRuleEngine::BuildScanEvaluationContent(
        const RuleSnapshot& snapshot,
        const std::string& currentContent,
        const ScanContextAppendDecision& appendDecision,
        uint64_t nowMs,
        ScanContextBuildInfo& info)
{
    const ScanContextConfig& config = snapshot.scanContext;
    info.snapshotHash = snapshot.effectiveHash;
    info.currentLen = currentContent.size();
    info.enabled = config.enabled && config.maxBufferedBytes != 0;
    info.appendAllowed = appendDecision.Allowed();
    info.appendSkipReason = appendDecision.reason;

    if (!appendDecision.Allowed()) {
        std::string eval = TrimStringTail(currentContent, config.maxEvalBytes);
        info.bufferedLen = 0;
        info.evalLen = eval.size();
        LogWithSeverity(RaspDiagSeverity::Debug,
                        "scan_context enabled=%d current_len=%zu buffered_len=0 eval_len=%zu expired=0 append_allowed=0 append_skip_reason=%s",
                        info.enabled ? 1 : 0,
                        info.currentLen,
                        info.evalLen,
                        ScanContextAppendSkipReasonToString(info.appendSkipReason));
        return eval;
    }

    std::string contextCopy;
    bool expired = false;
    bool snapshotChanged = false;
    {
        std::lock_guard<std::mutex> lock(m_scanContextMutex);
        if (m_activeScanContextSnapshotHash.empty()) {
            m_activeScanContextSnapshotHash = snapshot.effectiveHash;
        } else if (m_activeScanContextSnapshotHash != snapshot.effectiveHash) {
            m_scanContextBuffer.clear();
            m_lastScanContextAppendMs = 0;
            m_activeScanContextSnapshotHash = snapshot.effectiveHash;
            snapshotChanged = true;
        }

        expired = m_lastScanContextAppendMs != 0 &&
                  nowMs - m_lastScanContextAppendMs > config.ttlMs;
        if (expired) {
            m_scanContextBuffer.clear();
            m_lastScanContextAppendMs = 0;
        }

        contextCopy = m_scanContextBuffer;
        info.bufferedLen = contextCopy.size();
        info.expired = expired;
    }

    if (snapshotChanged) {
        LogWithSeverity(RaspDiagSeverity::Debug,
                        "scan_context cleared reason=snapshot_changed");
    }
    if (expired) {
        LogWithSeverity(RaspDiagSeverity::Debug,
                        "scan_context cleared reason=ttl_expired");
    }

    std::string eval;
    if (!contextCopy.empty()) {
        eval.reserve(contextCopy.size() + 1 + currentContent.size());
        eval.append(contextCopy);
        eval.push_back('\n');
    } else {
        eval.reserve(currentContent.size());
    }
    eval.append(currentContent);
    TrimStringTailInPlace(eval, config.maxEvalBytes);
    info.evalLen = eval.size();

    LogWithSeverity(RaspDiagSeverity::Debug,
                    "scan_context enabled=1 current_len=%zu buffered_len=%zu eval_len=%zu expired=%d append_allowed=1 append_skip_reason=none appended=0 cleared_on_match=0",
                    info.currentLen,
                    info.bufferedLen,
                    info.evalLen,
                    info.expired ? 1 : 0);

    return eval;
}

void AmsiRuleEngine::FinalizeScanContext(
        const RuleSnapshot& snapshot,
        const std::string& currentContent,
        uint64_t nowMs,
        const ScanContextFinalizeResult& result,
        const ScanContextBuildInfo& buildInfo)
{
    const ScanContextConfig& config = snapshot.scanContext;
    if (!config.enabled || config.maxBufferedBytes == 0)
        return;
    if (!buildInfo.appendAllowed)
        return;
    if (currentContent.empty())
        return;

    std::lock_guard<std::mutex> lock(m_scanContextMutex);
    auto current = std::atomic_load(&m_snapshot);
    if (!current || current->effectiveHash != snapshot.effectiveHash)
        return;
    if (!m_activeScanContextSnapshotHash.empty() &&
        m_activeScanContextSnapshotHash != snapshot.effectiveHash)
        return;

    if (result.matched && config.clearOnMatch) {
        m_scanContextBuffer.clear();
        m_lastScanContextAppendMs = 0;
        m_activeScanContextSnapshotHash = snapshot.effectiveHash;
        LogWithSeverity(RaspDiagSeverity::Debug,
                        "scan_context cleared reason=rule_match");
        return;
    }

    if (result.rateLimitedBypass || result.globalTimeout || result.exception)
        return;

    if (!m_scanContextBuffer.empty())
        m_scanContextBuffer.push_back('\n');
    m_scanContextBuffer.append(currentContent);
    TrimStringTailInPlace(m_scanContextBuffer, config.maxBufferedBytes);
    m_lastScanContextAppendMs = nowMs;
    m_activeScanContextSnapshotHash = snapshot.effectiveHash;
}

void AmsiRuleEngine::ClearScanContext(const char* reason)
{
    bool hadContext = false;
    {
        std::lock_guard<std::mutex> lock(m_scanContextMutex);
        hadContext = !m_scanContextBuffer.empty() || m_lastScanContextAppendMs != 0;
        m_scanContextBuffer.clear();
        m_lastScanContextAppendMs = 0;
        m_activeScanContextSnapshotHash.clear();
    }

    if (hadContext) {
        LogWithSeverity(RaspDiagSeverity::Debug,
                        "scan_context cleared reason=%s",
                        reason ? reason : "unknown");
    }
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

    const char* reason = "none";
    if (exec.timedOut && !exec.timeoutReason.empty())
        reason = exec.timeoutReason.c_str();
    else if (exec.regexRuleLimitHit)
        reason = "regex_pattern_limit";

    const char* decision = exec.decisionAfterTimeout.empty()
        ? (exec.regexRuleLimitHit && !exec.timedOut ? "continue" : "none")
        : exec.decisionAfterTimeout.c_str();

    char msg[640];
    snprintf(msg, sizeof(msg),
             "[RaspAmsi][telemetry] scan_budget reason=%s decision=%s rules=%u max_rules=%u regex_calls=%u max_regex_calls=%u lua_instr=%u regex_limit=%s regex_rule_limit=%d rules_skipped_by_regex_limit=%u match_limit=%u depth_limit=%u heap_limit=%u jit_stack_limit=%u subject_truncated=%d matched_before_timeout=%d\n",
             reason,
             decision,
             exec.rulesEvaluated,
             exec.budget.maxRules,
             exec.regexCalls,
             exec.budget.maxRegexCalls,
             exec.luaInstructions,
             exec.regexLimitType.empty() ? "none" : exec.regexLimitType.c_str(),
             exec.regexRuleLimitHit ? 1 : 0,
             exec.rulesSkippedByRegexLimit,
             exec.regexMatchLimitHits,
             exec.regexDepthLimitHits,
             exec.regexHeapLimitHits,
             exec.regexJitStackLimitHits,
             exec.regexSubjectTruncated ? 1 : 0,
             exec.matchedBeforeTimeout ? 1 : 0);
    RaspLogWithSeverity(RaspDiagSeverity::Warning, "%s", msg);
}

void AmsiRuleEngine::PublishSnapshot(std::shared_ptr<const RuleSnapshot> next,
                                     const std::string &effectiveLib) {
    if (!next)
        return;

    ClearScanContext("snapshot_changed");
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
    ClearScanContext("reload");
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
    for (size_t ruleIndex = 0; ruleIndex < rules.size(); ++ruleIndex) {
        const auto &rule = rules[ruleIndex];
#ifdef RASP_PCRE2_AVAILABLE
        luaEngine.PrecompileRegex(rule.regexPatterns, static_cast<int>(ruleIndex), -1);
        for (size_t checkIndex = 0; checkIndex < rule.regexChecks.size(); ++checkIndex) {
            const auto &check = rule.regexChecks[checkIndex];
            luaEngine.PrecompileRegex(check.patterns,
                                      static_cast<int>(ruleIndex),
                                      static_cast<int>(checkIndex));
        }
#endif

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
    std::vector<size_t> blockRuleIndexes;
    std::vector<size_t> alertRuleIndexes;
    blockRuleIndexes.reserve(rules.size());
    alertRuleIndexes.reserve(rules.size());
    for (size_t i = 0; i < rules.size(); ++i) {
        if (rules[i].IsBlock()) {
            blockRuleIndexes.push_back(i);
        } else {
            alertRuleIndexes.push_back(i);
        }
    }
    std::shared_ptr<const RuleSnapshot> next =
            std::make_shared<RuleSnapshot>(
                     RuleSnapshot{std::move(rules),
                                  std::move(blockRuleIndexes),
                                  std::move(alertRuleIndexes),
                                  {},
                                  std::make_shared<RaspLuaEngine>(),
                                  false,
                                  RaspGlobalMode::Block,
                                 kDefaultMaxScanContentBytes,
                                 kDefaultTotalScanTimeoutMs,
                                 kDefaultMaxRulesPerScan,
                                 kDefaultMaxRegexCallsPerScan,
                                 kDefaultAuditMaxEventsPerScan,
                                  true,
                                  ScanRateLimitConfig{},
                                  ScanContextConfig{},
                                  DiagnosticsConfig{},
                                  {}});
    std::atomic_store(&m_snapshot, next);
}

void AmsiRuleEngine::FillDiagnosticLogContext(LegacyDiagJsonBuildInput& input) const
{
    auto processSnapshot = GetProcessContextProvider().GetSnapshot();
    const ProcessContextSnapshot& process = *processSnapshot;

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

        WriteDrainAckWithTimeout(ackLine, 200);

        return 0;
        }

void AmsiRuleEngine::OnUnloadSignal() {
    ClearScanContext("unload");
    HANDLE hThread = CreateThread(nullptr, 0, UnloadThreadProc, nullptr, 0, nullptr);
    if (hThread)
        CloseHandle(hThread);
    else
        LogWithSeverity(RaspDiagSeverity::Error, "OnUnloadSignal: failed to create unload thread - inert mode remains active");
}

void AmsiRuleEngine::OnPauseDetectionSignal()
{
    ClearScanContext("pause");
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

    ClearScanContext("resume");
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
    exec.budget.totalBudgetMs = snap->totalScanTimeoutMs;
    exec.budget.maxRules = snap->maxRulesPerScan;
    exec.budget.maxRegexCalls = snap->maxRegexCallsPerScan;
    exec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec.budget.totalBudgetMs));
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
    std::string amsiSampleLen;
    std::string normalizerRawLen;
    std::string normalizerNormalizedLen;
    std::string normalizerMaxScanContentBytes;
    std::string normalizerTruncated;
    std::string normalizerUtf16;
    std::string normalizerBase64;
    std::string normalizerNulls;
    for (const auto &f: ctx.fields) {
        if (f.name == "contentName")
            contentName = f.value;
        else if (f.name == "appName")
            appName = f.value;
        else if (f.name == "__amsiSampleLen")
            amsiSampleLen = f.value;
        else if (f.name == "__normalizerRawLen")
            normalizerRawLen = f.value;
        else if (f.name == "__normalizerNormalizedLen")
            normalizerNormalizedLen = f.value;
        else if (f.name == "__normalizerMaxScanContentBytes")
            normalizerMaxScanContentBytes = f.value;
        else if (f.name == "__normalizerTruncated")
            normalizerTruncated = f.value;
        else if (f.name == "__normalizerUtf16")
            normalizerUtf16 = f.value;
        else if (f.name == "__normalizerBase64")
            normalizerBase64 = f.value;
        else if (f.name == "__normalizerNulls")
            normalizerNulls = f.value;
    }

    if (TrustProcessMatches(snap->trustProcessPaths, scanContext, nullptr)) {
        return results;
    }

    const uint64_t scanNowMs = GetTickCount64();
    const ScanRateLimitDecision rateDecision =
        ShouldBypassByScanRateLimit(snap->scanRateLimit, scanNowMs);
    if (rateDecision.bypass)
        return results;

    std::string currentBody;
    for (const auto& f : ctx.fields) {
        if (f.name == "body") {
            currentBody = f.value;
            break;
        }
    }

    RaspLuaContext evalCtx = ctx;
    ScanContextBuildInfo contextInfo;
    if (!currentBody.empty()) {
        LogWithSeverity(RaspDiagSeverity::Debug,
                        "[AMSI:Scan] sampleLen=%s evalLen=%zu",
                        amsiSampleLen.empty() ? "0" : amsiSampleLen.c_str(),
                        currentBody.size());
        LogWithSeverity(RaspDiagSeverity::Debug,
                        "normalizer rawLen=%s normalizedLen=%s maxScanContentBytes=%s truncated=%s utf16=%s b64=%s nulls=%s",
                        normalizerRawLen.empty() ? "0" : normalizerRawLen.c_str(),
                        normalizerNormalizedLen.empty() ? "0" : normalizerNormalizedLen.c_str(),
                        normalizerMaxScanContentBytes.empty() ? "0" : normalizerMaxScanContentBytes.c_str(),
                        normalizerTruncated.empty() ? "0" : normalizerTruncated.c_str(),
                        normalizerUtf16.empty() ? "0" : normalizerUtf16.c_str(),
                        normalizerBase64.empty() ? "0" : normalizerBase64.c_str(),
                        normalizerNulls.empty() ? "0" : normalizerNulls.c_str());

        const ScanContextAppendDecision appendDecision =
            ShouldAppendToScanContext(contentName, currentBody, snap->scanContext);
        const std::string evalBody =
            BuildScanEvaluationContent(*snap, currentBody, appendDecision, scanNowMs, contextInfo);
        const ScanContentDebugDumpInfo dumpInfo{
            contextInfo.enabled,
            contextInfo.appendAllowed,
            contextInfo.appendSkipReason,
            contextInfo.currentLen,
            contextInfo.bufferedLen,
            contextInfo.evalLen,
            contextInfo.expired,
            contextInfo.snapshotHash
        };
        if (snap->diagnostics.scanDumpLog) {
            WriteScanContentDebugDump(scanContext ? scanContext->process : nullptr,
                                      contentName,
                                      appName,
                                      dumpInfo,
                                      currentBody,
                                      evalBody,
                                      snap->diagnostics.scanDumpMaxBytes);
        }
        for (auto& f : evalCtx.fields) {
            if (f.name == "body") {
                f.value = evalBody;
                f.isBinary = true;
                break;
            }
        }
    } else {
        contextInfo.enabled = snap->scanContext.enabled && snap->scanContext.maxBufferedBytes != 0;
        contextInfo.appendAllowed = false;
        contextInfo.appendSkipReason = ScanContextAppendSkipReason::EmptyBody;
        contextInfo.snapshotHash = snap->effectiveHash;
    }

    const bool perfLogEnabled = snap->diagnostics.perfLog;
    const uint64_t ruleEvalStartMs = perfLogEnabled ? GetTickCount64() : 0;

    struct RuleGroupStats {
        uint32_t rulesVisited = 0;
        uint32_t regexCalls = 0;
        bool matched = false;
        bool blockMatched = false;
    };

    uint32_t nonBlockEventsEmitted = 0;
    const bool globalAuditMode = snap->hasGlobalMode && snap->globalMode == RaspGlobalMode::Audit;
    RuleGroupStats blockStats;
    RuleGroupStats alertStats;

    auto evaluateRuleGroup = [&](const std::vector<size_t>& ruleIndexes,
                                 bool allowBlock,
                                 RuleGroupStats& stats) -> bool {
        const uint32_t regexCallsBeforeGroup = exec.regexCalls;
        for (size_t ruleIndexValue : ruleIndexes) {
            if (ruleIndexValue >= snap->rules.size())
                continue;

            const auto &rule = snap->rules[ruleIndexValue];
            exec.SetRuleContext(static_cast<int>(ruleIndexValue));
            exec.ClearCurrentRuleLimit();
            if (!exec.TryEnterRule()) {
                stats.regexCalls += exec.regexCalls - regexCallsBeforeGroup;
                return true;
            }
            ++stats.rulesVisited;

            if (!rule.enabled || rule.IsOff())
                continue;

            // Parent path gate is rule-local: skip only this rule and keep
            // evaluating later rules in the same scan.
            if (!ParentPathGatePasses(rule, scanContext))
                continue;

            bool matched = false;
            bool skipCurrentRule = false;
            std::string desc;
            std::string payload;

            auto skipRuleForRegexLimit = [&]() {
                ++exec.rulesSkippedByRegexLimit;
                LogWithSeverity(RaspDiagSeverity::Debug,
                                "Evaluate: ruleIndex=%d checkIndex=%d patternIndex=%d skipped because regex pattern limit hit type=%s",
                                exec.currentRuleIndex,
                                exec.currentRegexCheckIndex,
                                exec.currentRegexPatternIndex,
                                exec.currentRuleLimitType.empty() ? "unknown" : exec.currentRuleLimitType.c_str());
                exec.ClearCurrentRuleLimit();
            };

#ifdef RASP_PCRE2_AVAILABLE
            // 优先匹配正则表达式
            if (!rule.regexChecks.empty()) {
                // ── Multi-check gate (regexChecks) ─────────────────────────────
                // Evaluate each named check; collect IDs of checks that matched.
                std::vector<std::string> matchedIds;
                for (size_t checkIndex = 0; checkIndex < rule.regexChecks.size(); ++checkIndex) {
                    const auto &chk = rule.regexChecks[checkIndex];
                    exec.SetRegexCheckContext(static_cast<int>(checkIndex));
                    const std::string *fp = nullptr;
                    const std::string &want = chk.field.empty() ? std::string("body") : chk.field;
                    for (const auto &f : evalCtx.fields)
                        if (f.name == want) {
                            fp = &f.value;
                            break;
                        }
                    std::string mp;
                    if (fp && !fp->empty() &&
                        luaEngine.MatchesAnyRegex(chk.patterns, *fp, mp, &exec))
                        matchedIds.push_back(chk.id);
                    if (exec.currentRuleLimited) {
                        skipCurrentRule = true;
                        break;
                    }
                    if (exec.ShouldStopScan())
                        break;
                }
                if (exec.currentRuleLimited) {
                    skipCurrentRule = true;
                }
                if (skipCurrentRule) {
                    skipRuleForRegexLimit();
                    continue;
                }
                if (exec.ShouldStopScan()) {
                    stats.regexCalls += exec.regexCalls - regexCallsBeforeGroup;
                    return true;
                }
                bool gatePassed = (rule.regexCondition == RegexCondition::All)
                    ? matchedIds.size() == rule.regexChecks.size()
                    : !matchedIds.empty();
                if (!gatePassed)
                    continue; // gate not satisfied — skip rule

                if (luaEngine.IsLoaded(rule.id))
                {
                    // Gate passed → run Lua with matched IDs injected into context
                    RaspLuaResult lr = luaEngine.Run(rule.id, sensor, evalCtx, rule.scriptTimeoutInstructions, matchedIds, &exec);
                    if (lr.timedOut || exec.ShouldStopScan()) {
                        stats.regexCalls += exec.regexCalls - regexCallsBeforeGroup;
                        return true;
                    }
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
                for (const auto &f : evalCtx.fields)
                    if (f.name == wantField) { fieldPtr = &f.value; break; }
                if (fieldPtr && !fieldPtr->empty())
                {
                    exec.SetRegexCheckContext(-1);
                    std::string matchedPat;
                    if (luaEngine.MatchesAnyRegex(rule.regexPatterns, *fieldPtr, matchedPat, &exec))
                    {
                        matched = true;
                        desc    = rule.description;
                        payload = matchedPat;
                    }
                    if (exec.currentRuleLimited) {
                        skipCurrentRule = true;
                    }
                    if (exec.ShouldStopScan()) {
                        stats.regexCalls += exec.regexCalls - regexCallsBeforeGroup;
                        return true;
                    }
                }
            }
#endif // RASP_PCRE2_AVAILABLE

            if (skipCurrentRule) {
                skipRuleForRegexLimit();
                continue;
            }

            // ── lua脚本check, PrecompileAll在这里预编译, 可以不走此部分 ─
            if (!matched && rule.regexChecks.empty() && luaEngine.IsLoaded(rule.id)) {
                RaspLuaResult lr = luaEngine.Run(rule.id, sensor, evalCtx,
                                                 rule.scriptTimeoutInstructions,
                                                 {},
                                                 &exec);
                if (lr.timedOut || exec.ShouldStopScan()) {
                    stats.regexCalls += exec.regexCalls - regexCallsBeforeGroup;
                    return true;
                }
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
            r.block = allowBlock && ShouldBlockRule(*snap, rule);
            r.ruleId = rule.id;
            r.sensor = sensor;
            r.desc = desc;
            r.payload = payload;
            r.severity = rule.severity;
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
            stats.matched = true;
            if (shouldBlock)
                stats.blockMatched = true;
            results.push_back(std::move(r));
            if (shouldBlock && snap->stopAfterFirstBlock) {
                stats.regexCalls += exec.regexCalls - regexCallsBeforeGroup;
                return true;
            }
            if (!shouldBlock)
                ++nonBlockEventsEmitted;
            if (!shouldBlock && snap->auditMaxEventsPerScan > 0 &&
                nonBlockEventsEmitted >= snap->auditMaxEventsPerScan) {
                LogWithSeverity(RaspDiagSeverity::Debug,
                                "scanOptimization: auditMaxEventsPerScan reached for non-block events, stop evaluating remaining rules");
                stats.regexCalls += exec.regexCalls - regexCallsBeforeGroup;
                return true;
            }
        }
        stats.regexCalls += exec.regexCalls - regexCallsBeforeGroup;
        return false;
    };

    bool stopEvaluation = false;
    if (globalAuditMode) {
        stopEvaluation = evaluateRuleGroup(snap->blockRuleIndexes, false, blockStats);
        if (!stopEvaluation)
            stopEvaluation = evaluateRuleGroup(snap->alertRuleIndexes, false, alertStats);
    } else {
        stopEvaluation = evaluateRuleGroup(snap->blockRuleIndexes, true, blockStats);
        if (!stopEvaluation)
            stopEvaluation = evaluateRuleGroup(snap->alertRuleIndexes, false, alertStats);
    }

    if (exec.timedOut)
        ResolveTimeoutDecision(results, exec);
    EmitScanBudgetTelemetry(exec);
    ScanContextFinalizeResult contextResult;
    contextResult.matched = !results.empty();
    contextResult.globalTimeout = exec.timedOut;
    if (perfLogEnabled) {
        bool hasBlock = false;
        for (const auto& item : results) {
            if (item.block) {
                hasBlock = true;
                break;
            }
        }
        const uint64_t costMs = GetTickCount64() - ruleEvalStartMs;
        const uint32_t rulesVisited = blockStats.rulesVisited + alertStats.rulesVisited;
        LogWithSeverity(RaspDiagSeverity::Debug,
                        "[RaspAmsi][perf] rule_eval costMs=%llu rulesVisited=%lu rulesTotal=%zu maxRules=%u regexCalls=%u maxRegexCalls=%u regexPrefixSkips=%u matched=%d block=%d timedOut=%d currentLen=%zu evalLen=%zu appendAllowed=%d appendSkipReason=%s blockRulesVisited=%lu alertRulesVisited=%lu blockRegexCalls=%lu alertRegexCalls=%lu blockMatched=%d alertMatched=%d",
                        static_cast<unsigned long long>(costMs),
                        static_cast<unsigned long>(rulesVisited),
                        snap->rules.size(),
                        exec.budget.maxRules,
                        exec.regexCalls,
                        exec.budget.maxRegexCalls,
                        exec.regexPrefixSkips,
                        results.empty() ? 0 : 1,
                        hasBlock ? 1 : 0,
                        exec.timedOut ? 1 : 0,
                        contextInfo.currentLen,
                        contextInfo.evalLen,
                        contextInfo.appendAllowed ? 1 : 0,
                        ScanContextAppendSkipReasonToString(contextInfo.appendSkipReason),
                        static_cast<unsigned long>(blockStats.rulesVisited),
                        static_cast<unsigned long>(alertStats.rulesVisited),
                        static_cast<unsigned long>(blockStats.regexCalls),
                        static_cast<unsigned long>(alertStats.regexCalls),
                        blockStats.matched ? 1 : 0,
                        alertStats.matched ? 1 : 0);
    }
    FinalizeScanContext(*snap, currentBody, scanNowMs, contextResult, contextInfo);
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
    ctx.fields.push_back({"__amsiSampleLen", std::to_string(sampleLen)});
    ctx.fields.push_back({"__normalizerRawLen", std::to_string(normalized.rawLen)});
    ctx.fields.push_back({"__normalizerNormalizedLen", std::to_string(normalized.normalizedLen)});
    ctx.fields.push_back({"__normalizerMaxScanContentBytes", std::to_string(maxScanContentBytes)});
    ctx.fields.push_back({"__normalizerTruncated", normalized.truncated ? "1" : "0"});
    ctx.fields.push_back({"__normalizerUtf16", normalized.decodedUtf16Le ? "1" : "0"});
    ctx.fields.push_back({"__normalizerBase64", normalized.decodedBase64 ? "1" : "0"});
    ctx.fields.push_back({"__normalizerNulls", normalized.hadNullBytes ? "1" : "0"});
    if (!normalized.normalized.empty()) {
        ctx.fields.push_back({"body", normalized.normalized, true});
        ctx.fields.push_back({"script_content", TruncateForEventField(normalized.normalized, kMaxScriptContentEventBytes)});
    }

    auto results = Evaluate("AmsiProvider", ctx);  // 调用真正的 Evaluate 函数
    for (const auto &r : results) {
        if (!r.matched)
            continue;

        if (!result.ruleMatched) {
            result.ruleMatched = true;
            result.block = r.block;
            result.ruleId = r.ruleId;
            result.desc = r.desc;
            result.payload = r.payload;
            result.severity = r.severity;
        }

        if (r.block) {
            result.ruleMatched = true;
            result.block = true;
            result.ruleId = r.ruleId;
            result.desc = r.desc;
            result.payload = r.payload;
            result.severity = r.severity;
            break;
        }
    }

    return result;
}
