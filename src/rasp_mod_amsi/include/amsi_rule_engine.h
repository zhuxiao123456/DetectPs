#pragma once
// =========================================================================
// amsi_rule_engine.h — in-process rule evaluation for rasp_mod_amsi
//
// Derives from RaspSentryBase (rasp_rule_engine static library) which
// provides: ring-buffer log, ConnectSentry IPC, ParseRulesJson, threads
// (LogForward, ConfigPipe, SentryRetry), Initialize/Shutdown, Evaluate().
//
// This class adds AMSI-specific concerns:
//   - AmsiRaspRuleConfig : RaspRuleBase — concrete rule type (no extra fields)
//   - AmsiEvalResult                    — public scan result (AMSI API surface)
//   - Public Evaluate(wchar_t*, ...)    — AMSI provider entry point
//   - Protected Evaluate(sensor, ctx)   — implements RaspSentryBase pure virtual
//   - ParseAndSwap()                    — builds typed snapshot, precompiles Lua
//   - OnReloadSignal()                  — retries ConnectSentry+ParseAndSwap
//   - OnUnloadSignal()                  — self-unload via FreeLibraryAndExitThread
//
// All configuration is sourced exclusively from rasp_sentry via IPC.
// Named pipes:
//   \\.\pipe\rasp_sentry_rules   — 启动|重载时的拉取规则
//   \\.\pipe\rasp_sentry_events  — 推送JSONL事件和诊断日志
//   \\.\pipe\rasp_sentry_config  — 接收0x01重新加载信号
// =========================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>
#include <vector>
#include <atomic>
#include <cstdint>

#include "rasp_sentry_base.h"  // from rasp_rule_engine static library

// ── AmsiRaspRuleConfig ────────────────────────────────────────────────────
// Naming convention: <Module>RaspRuleConfig — defined as a proper struct
// (not typedef/alias) for symmetry with Iis7RaspRuleConfig, forward-declaration
// support, and future AMSI-specific field extensibility.
// All current AMSI rule fields are inherited from RaspRuleBase.
struct AmsiRaspRuleConfig : public RaspRuleBase {};  // 定义 AMSI 专属的具体规则实体


// ── AmsiEvalResult ────────────────────────────────────────────────────────
// Public result type for IAntimalwareProvider::Scan() callers.
// Populated by the public Evaluate() from the first matching RaspEvalResult.
struct AmsiEvalResult
{
    bool        ruleMatched = false;
    bool        block       = false;
    std::string ruleId;
    std::string desc;
    std::string payload;
    std::string severity;
};

// ── AmsiRuleEngine ────────────────────────────────────────────────────────
class AmsiRuleEngine : public RaspSentryBase
{
public:
    // windows调用->scan->转换为utf-8->构建RaspLuaContext->调用protected Evaluate()->RaspEvalResult(检测结果)->AmsiEvalResult
    AmsiEvalResult Evaluate(
        const wchar_t* contentName,
        const wchar_t* appName,
        const char*    sample,
        ULONG          sampleLen);

    // 真正调用lua脚本的函数
    std::vector<RaspEvalResult> Evaluate(
        const std::string&    sensor,
        const RaspLuaContext& ctx) override;

protected:
    // ── Virtual factory ───────────────────────────────────────────────────
    RaspRuleBase* AllocRule() const override { return new AmsiRaspRuleConfig(); }

    // Handles the "config" JSON sub-object to extract regexField / regexPatterns
    // (stored in RaspRuleBase).  All other config keys are skipped.
    void ParseRuleExtension(const std::string& key,
                            void*              parserPtr,
                            RaspRuleBase&      rule) override;

    // ── 生命周期与 IPC 钩子 ───────────────────────────────────────────────────
    bool ParseAndSwap(const std::string& json,
                      const std::string& libSource) override;
    void OnReloadSignal() override;
    void OnUnloadSignal() override;

    const char* ModuleName()      const override { return "rasp_mod_amsi"; }
    const char* LogEventPattern() const override { return "amsi-log"; }

private:
    struct RuleSnapshot { std::vector<AmsiRaspRuleConfig> rules; };
    std::atomic<RuleSnapshot*> m_snapshot{ nullptr };  // 原子快照机制，使用 std::atomic 存储指针，在 SwapRules 时只需一次 CPU 原子的指针替换指令
    std::string                m_libSource;  // 存储编译好的lua检测脚本

    void PrecompileAll(const std::vector<AmsiRaspRuleConfig>& rules,
                       const std::string& libSource);
    void SwapRules(std::vector<AmsiRaspRuleConfig>&& rules);

    static DWORD WINAPI UnloadThreadProc(LPVOID);
};

// Global singleton — initialised in DllMain
extern AmsiRuleEngine*    g_engine;
extern HINSTANCE          g_hModule;          // captured in DllMain; used by UnloadThreadProc
extern std::atomic<bool>  g_unloadInProgress; // set before Scan() starts ignoring scans
