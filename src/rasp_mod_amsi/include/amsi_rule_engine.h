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
#include <string>
#include <vector>

#include "rasp_sentry_base.h"
#include "script_input_normalizer.h"

struct ScanContext;

struct AmsiRaspRuleConfig : public RaspRuleBase {};

struct AmsiEvalResult
{
    bool        ruleMatched = false;
    bool        block       = false;
    std::string ruleId;
    std::string desc;
    std::string payload;
    std::string severity;
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

    const char* ModuleName()      const override { return "rasp_mod_amsi"; }
    const char* LogEventPattern() const override { return "amsi-log"; }

protected:
    struct RuleSnapshot {
        std::vector<AmsiRaspRuleConfig> rules;
        std::shared_ptr<RaspLuaEngine> luaEngine;
    };

    std::shared_ptr<const RuleSnapshot> BuildNextSnapshot(
        const std::string& json,
        const std::string& libSource,
        std::string& effectiveLib);

private:
    ScriptInputNormalizer m_inputNormalizer;
    std::shared_ptr<const RuleSnapshot> m_snapshot;
    std::string m_libSource;

    void PublishSnapshot(std::shared_ptr<const RuleSnapshot> next,
                         const std::string& effectiveLib);
    void PrecompileAll(const std::vector<AmsiRaspRuleConfig>& rules,
                       const std::string& libSource,
                       RaspLuaEngine& luaEngine);
    void SwapRules(std::vector<AmsiRaspRuleConfig>&& rules);

    static DWORD WINAPI UnloadThreadProc(LPVOID);
};

extern HINSTANCE g_hModule;
