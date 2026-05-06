#pragma once
// =========================================================================
// rasp_sentry_base.h — Abstract base class shared by all RASP native modules.
//
// Provides once-written infrastructure:
//   - Ring-buffer diagnostic log  (RaspLog → rasp_sentry_events pipe)
//   - ConnectSentry()             (GET_ALL_RULES IPC handshake)
//   - ParseRulesJson()            (recursive-descent, calls ParseRuleExtension hook)
//   - SendDetectionEvent()        (fire-and-forget JSONL to rasp_sentry_events)
//   - LogForwardThread            (async ring-buffer drain to pipe)
//   - ConfigPipeThread            (0x01 reload signal server)
//   - SentryRetryThread           (unconditional; active retry until first load)
//   - Initialize() / Shutdown()   (lifecycle)
//   - virtual Evaluate()          (sensor-dispatch entry point)
//
// Each module (IIS7, AMSI, …) provides:
//   - AllocRule()       — virtual factory; return module's derived RaspRuleBase type
//   - ParseAndSwap()    — build snapshot from parsed rules, precompile Lua
//   - OnReloadSignal()  — retries ConnectSentry + ParseAndSwap (called by ConfigPipeThread)
//   - ParseRuleExtension() — fills module-specific fields for each unrecognised JSON key
//   - Evaluate()        — applies module-specific C++ guards + Lua; returns results
//   - ModuleName()      — "rasp_mod_iis7" / "rasp_mod_amsi"
//   - LogEventPattern() — "iis7-log" / "amsi-log"
// =========================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>
#include <vector>
#include <memory>
#include <atomic>

#include "rasp_lua_engine.h"
#include "rasp_rule_base.h"
#include "async_event_queue.h"
#include "rule_json_parser.h"

// ── RaspEvalResult ────────────────────────────────────────────────────────
// Returned by Evaluate() per matched rule. url/method/ip/ua are populated by
// the module's Evaluate() so SendDetectionEvent() can build full JSONL without
// module-specific arguments.
struct RaspEvalResult
{
    bool        matched   = false;
    bool        block     = false;
    std::string ruleId;
    std::string sensor;
    std::string desc;
    std::string payload;
    std::string severity;
    // Request context for JSONL serialization:
    std::string contentName;      // IIS7: normalized path;  AMSI: contentName (UTF-8)
    std::string appName;   // IIS7: HTTP verb;         AMSI: appName (UTF-8)
    std::string ip;       // IIS7: client IP;         AMSI: ""
    std::string ua;       // IIS7: User-Agent header; AMSI: ""
    int confidence;  // 置信度
};

// ── RaspSentryBase ────────────────────────────────────────────────────────
class RaspSentryBase
{
public:
    void Initialize();
    void Shutdown();

    // Diagnostic log — thread-safe; enqueues to ring buffer; drains async to sentry pipe.
    // Module .cpp keeps a thin RaspLog(fmt,...) free function that calls g_engine->Log().
    void Log(const char* fmt, ...) const;

    // Unified evaluation entry point — each module implements for its sensor set.
    // Returns all matched rules (multi-rule firing supported). Called by each module's
    // public-facing method after building RaspLuaContext from request/scan data.
    virtual std::vector<RaspEvalResult> Evaluate(
        const std::string&    sensor,
        const RaspLuaContext& ctx) = 0;

protected:
    // ── Shared state ─────────────────────────────────────────────────────
    RaspLuaEngine     m_luaEngine;
    std::atomic<bool> m_running{false};

    // ── IPC ──────────────────────────────────────────────────────────────
    // Connect to \\.\pipe\rasp_sentry_rules, send GET_ALL_RULES\n, read response.
    // On success: jsonOut contains raw response; libSourceOut contains decoded
    // globalLibrariesBase64 (rasp_lib.lua source, '\n'-joined).
    bool ConnectSentry(std::string& jsonOut, std::string& libSourceOut);

    static bool Base64Decode(const std::string& b64, std::string& out);

    // ── Shared JSON parser ────────────────────────────────────────────────
    // Parser context remains available to derived ParseRuleExtension() handlers.
    using Parser = RuleJsonParser::Parser;

    // Parse GET_ALL_RULES response JSON.
    // Accumulates globalLibrariesBase64 into libSourceOut.
    // Allocates rule objects via AllocRule() (virtual factory — derived class may
    // return module-specific subtype). For each unrecognised JSON key, calls
    // ParseRuleExtension(key, &parser, *rule) so derived classes can fill extra fields.
    // The allocated objects are owned by the returned unique_ptr vector.
    bool ParseRulesJson(
        const std::string&                           json,
        std::string&                                 libSourceOut,
        std::vector<std::unique_ptr<RaspRuleBase>>&  rulesOut);

    // Virtual factory — override to return module-specific derived type.
    // Default returns new RaspRuleBase().
    // The returned pointer is stored in a unique_ptr<RaspRuleBase>; the downcast
    // in ParseRuleExtension is safe because the actual object is the derived type.
    virtual RaspRuleBase* AllocRule() const { return new RaspRuleBase(); }

    // Called by ParseRulesJson for each JSON key not handled by the base parser.
    // parserPtr is Parser* — cast and call read_*/skip_value() to consume the value.
    // baseRule's actual runtime type is whatever AllocRule() returned, so a downcast
    // to the derived type is safe.
    // Default: skip the value (no-op — AMSI needs no override).
    virtual void ParseRuleExtension(const std::string& key,
                                    void*              parserPtr,
                                    RaspRuleBase&      rule);

    // Fire-and-forget JSONL detection event to \\.\pipe\rasp_sentry_events.
    // Non-blocking: returns immediately if pipe unavailable (event silently dropped).
    // Replaces amsi_event_sender::SendAmsiEvent() — used by all modules.
    void SendDetectionEvent(const RaspEvalResult& result) const;
    EnqueueResult TrySubmitDetectionEvent(const RaspEvalResult& result) const;

    // Worker-only. Must never be called from Scan hot path.
    bool SendDetectionEventSyncWorkerOnly(const AsyncEvent& event) const;

    // Called after ConnectSentry() succeeds — module parses JSON into its typed
    // snapshot, precompiles Lua scripts, and swaps atomically.
    // Returns false if JSON is unparseable (snapshot left unchanged).
    virtual bool ParseAndSwap(const std::string& json,
                              const std::string& libSource) = 0;

    // Called by ConfigPipeThread on 0x01 signal — module retries ConnectSentry
    // and calls ParseAndSwap(); keeps existing snapshot if sentry unavailable.
    virtual void OnReloadSignal() = 0;

    // Called by ConfigPipeThread on 0x02 signal — module stops scanning and
    // unloads the DLL from the host process.  Default: no-op (IIS module ignores
    // the unload signal; only AMSI overrides this).
    virtual void OnUnloadSignal() {}

    virtual const char* ModuleName()      const = 0; // e.g. "rasp_mod_iis7"
    virtual const char* LogEventPattern() const = 0; // e.g. "iis7-log"

private:
    // ── Ring buffer (diagnostic log) ──────────────────────────────────────
    static const int kLogQueueCap = 256;
    struct LogEntry { char text[1024]; };
    LogEntry         m_logQueue[kLogQueueCap]{};
    volatile LONG    m_logHead        = 0;
    volatile LONG    m_logTail        = 0;
    volatile LONG    m_logCount       = 0;
    CRITICAL_SECTION m_logCs{};
    HANDLE           m_logEvent       = nullptr;
    bool             m_logCsReady     = false;
    volatile bool    m_logThreadAlive = false;

    void EnsureLogCsInit();
    void EnqueueLog(const char* text);
    // Requires m_logCs to be held by caller.
    void PushLogEntryLocked(const char* text);

    // ── Background threads ────────────────────────────────────────────────
    HANDLE m_logThread    = INVALID_HANDLE_VALUE;
    HANDLE m_configThread = INVALID_HANDLE_VALUE;
    // Unconditional for all modules — active polling handles AMSI processes
    // that start before rasp_sentry (passive reload signal would never reach them).
    HANDLE m_retryThread  = INVALID_HANDLE_VALUE;
    mutable AsyncEventSink m_eventSink;

    static DWORD WINAPI LogForwardThreadProc(LPVOID param);
    static DWORD WINAPI ConfigPipeThreadProc(LPVOID param);
    static DWORD WINAPI SentryRetryThreadProc(LPVOID param);
};
