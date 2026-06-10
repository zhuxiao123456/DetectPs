#pragma once
// =========================================================================
// amsi_rule_engine.h - in-process rule evaluation for rasp_mod_amsi
// =========================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "rasp_sentry_base.h"
#include "script_input_normalizer.h"

struct ScanContext;

struct AmsiRaspRuleConfig : public RaspRuleBase {
    std::vector<std::string> parentPathAllowContains;
    std::vector<std::string> parentPathBlockContains;
};

struct AmsiEvalResult
{
    bool        ruleMatched = false;
    bool        block       = false;
    std::string ruleId;
    std::string desc;
    std::string payload;
    int severity = 2;
};

class AmsiRuleEngine : public RaspSentryBase
{
public:
    AmsiEvalResult Evaluate(
        const wchar_t* contentName,
        const wchar_t* appName,
        const char*    sample,
        ULONG          sampleLen);
    AmsiEvalResult Evaluate(
        const wchar_t* contentName,
        const wchar_t* appName,
        const char*    sample,
        ULONG          sampleLen,
        const ScanContext& scanContext);

    std::vector<RaspEvalResult> Evaluate(
        const std::string&    sensor,
        const RaspLuaContext& ctx) override;

protected:
    RaspRuleBase* AllocRule() const override { return new AmsiRaspRuleConfig(); }

    void ParseRuleExtension(const std::string& key,
                            void*              parserPtr,
                            RaspRuleBase&      rule) override;

    bool ParseAndSwap(const std::string& json,
                      const std::string& libSource) override;
    void OnReloadSignal() override;
    void OnUnloadSignal() override;
    void OnPauseDetectionSignal() override;
    void OnResumeDetectionSignal() override;

    const char* ModuleName()      const override { return "hss_amsi"; }
    size_t ActiveRuleCountForStatus() const override;
    void FillDiagnosticLogContext(LegacyDiagJsonBuildInput& input) const override;

protected:
    struct RuleSnapshot {
        std::vector<AmsiRaspRuleConfig> rules;
        std::vector<std::string> trustProcessPaths;
        std::shared_ptr<RaspLuaEngine> luaEngine;
        bool hasGlobalMode = false;
        RaspGlobalMode globalMode = RaspGlobalMode::Block;
        uint32_t maxScanContentBytes = kDefaultMaxScanContentBytes;
        uint32_t totalScanTimeoutMs = kDefaultTotalScanTimeoutMs;
        uint32_t auditMaxEventsPerScan = kDefaultAuditMaxEventsPerScan;
        bool stopAfterFirstBlock = true;
        ScanRateLimitConfig scanRateLimit;
        ScanContextConfig scanContext;
        std::string effectiveHash;
    };

    struct ScanRateLimitDecision {
        bool enabled = false;
        bool overLimit = false;
        bool bypass = false;
        const char* reason = "";
        uint64_t windowScanCount = 0;
        uint64_t overLimitSeq = 0;
        uint32_t bypassPermille = 0;
    };

    struct ScanContextBuildInfo {
        bool enabled = false;
        size_t currentLen = 0;
        size_t bufferedLen = 0;
        size_t evalLen = 0;
        bool expired = false;
        std::string snapshotHash;
    };

    struct ScanContextFinalizeResult {
        bool matched = false;
        bool rateLimitedBypass = false;
        bool globalTimeout = false;
        bool exception = false;
    };

    std::shared_ptr<const RuleSnapshot> BuildNextSnapshot(
        const std::string& json,
        const std::string& libSource,
        std::string& effectiveLib);

    ScanRateLimitDecision ShouldBypassByScanRateLimit(
        const ScanRateLimitConfig& config,
        uint64_t nowMs);
    std::string BuildScanEvaluationContent(
        const RuleSnapshot& snapshot,
        const std::string& currentContent,
        uint64_t nowMs,
        ScanContextBuildInfo& info);
    void FinalizeScanContext(
        const RuleSnapshot& snapshot,
        const std::string& currentContent,
        uint64_t nowMs,
        const ScanContextFinalizeResult& result);
    void ClearScanContext(const char* reason);

private:
    ScriptInputNormalizer m_inputNormalizer;
    std::shared_ptr<const RuleSnapshot> m_snapshot;
    std::string m_libSource;
    std::mutex m_rateLimitMutex;
    uint64_t m_rateLimitWindowStartMs = 0;
    uint64_t m_rateLimitWindowScanCount = 0;
    uint64_t m_rateLimitOverLimitSeq = 0;
    uint32_t m_rateLimitWindowBypassed = 0;
    uint32_t m_rateLimitWindowEvaluatedAfterLimit = 0;
    bool m_rateLimitWindowLimitEntered = false;
    std::mutex m_scanContextMutex;
    std::string m_scanContextBuffer;
    uint64_t m_lastScanContextAppendMs = 0;
    std::string m_activeScanContextSnapshotHash;

    void PublishSnapshot(std::shared_ptr<const RuleSnapshot> next,
                         const std::string& effectiveLib);
    void PrecompileAll(const std::vector<AmsiRaspRuleConfig>& rules,
                       const std::string& libSource,
                       RaspLuaEngine& luaEngine);
    void SwapRules(std::vector<AmsiRaspRuleConfig>&& rules);
    static bool ShouldBlockRule(const RuleSnapshot& snapshot,
                                const RaspRuleBase& rule);
    std::vector<RaspEvalResult> EvaluateWithScanContext(
        const std::string& sensor,
        const RaspLuaContext& ctx,
        const ScanContext* scanContext);

    static DWORD WINAPI UnloadThreadProc(LPVOID);
};

extern HINSTANCE g_hModule;
