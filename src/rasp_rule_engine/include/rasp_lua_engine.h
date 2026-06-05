#pragma once
// =========================================================================
// rasp_lua_engine.h ¡ª Shared Lua 5.4 sandbox for native RASP modules.
//
// Used by rasp_mod_iis7 and rasp_mod_amsi (statically linked via
// rasp_rule_engine). Each module owns a RaspLuaEngine instance.
//
// Design principles:
//   Open context: each module populates only the fields it knows about.
//     Scripts see only what was pushed ¡ª no cross-module leakage.
//     A new module adds zero changes to this header.
//   Log injection: each module supplies its own RaspLuaLogFn backend.
//     IIS7 ¡ú OutputDebugStringA wrapper.
//     AMSI -> RaspLog wrapper (ring buffer -> amsi_detect_events IPC).
//   Per-request lua_State: no shared VM state, no lock contention.
//   Precompile cache: scripts are syntax-checked and cached by ruleId at
//     rulebook load time. Run() reads from cache ¡ª no re-parse per call.
// =========================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>

#include "rasp_scan_budget.h"
#include "legacy_diag_json_builder.h"

extern "C" {
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
}

#ifdef RASP_PCRE2_AVAILABLE
// Forward-declare the PCRE2 code object so we don't expose pcre2.h in this
// public header.  The implementation includes pcre2.h after defining
// PCRE2_CODE_UNIT_WIDTH 8, which produces pcre2_real_code_8.
struct pcre2_real_code_8;
#endif

// ©¤©¤ Context: open field-bag design ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤
// Each module populates only the fields it needs for its sensor scripts.
// Lua scripts only see the keys that were pushed ¡ª no cross-module field
// leakage, no nil-access errors from fields the module never set.
struct RaspLuaField
{
    std::string name;
    std::string value;
    bool        isBinary = false;  // true ¡ú lua_pushlstring (preserves null bytes in body)
};

struct RaspLuaContext
{
    std::vector<RaspLuaField>        fields;            // named string/binary fields
    const std::vector<std::string>*  arrayField     = nullptr; // optional 1-indexed Lua array
    std::string                      arrayFieldName;           // key for the array field
};

// ©¤©¤ Log injection ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤
// Supply a module-specific backend before calling Precompile/Run.
// The function receives an already-formatted, null-terminated string.
// IIS7: [](const char* m){ OutputDebugStringA(m); }     (wraps local RaspLog)
// AMSI: [](const char* m){ RaspLog("%s", m); }          (ring buffer ¡ú IPC)
using RaspLuaLogFn = void(*)(const char* msg);
using RaspLuaLeveledLogFn = void(*)(RaspDiagSeverity severity, const char* msg);

// ©¤©¤ Result ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤
struct RaspLuaResult
{
    bool        matched = false;
    bool        timedOut = false;
    std::string desc;
    std::string payload;
    std::string timeoutReason;
};

// ©¤©¤ Engine ©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤©¤
class RaspLuaEngine
{
public:
    ~RaspLuaEngine();

    // Inject module-specific logging backend. Call before Precompile/Run.
    void SetLogFn(RaspLuaLogFn fn);
    void SetLeveledLogFn(RaspLuaLeveledLogFn fn);

    // Syntax-check combinedSrc (libSource + "\n" + ruleScript) and cache under ruleId.
    // On syntax error: logs via m_logFn and does NOT cache.
    // IsLoaded returns false ¡ú module falls back to C++ checks.
    void Precompile(const std::string& ruleId,
                    const std::string& payload,
                    bool isBytecode = false);

    // Returns true if Precompile succeeded for ruleId.
    bool IsLoaded(const std::string& ruleId) const;

    // Evict all cached scripts. Call before each rulebook reload/hot-swap.
    void Reset();

    // Execute cached script for ruleId in a fresh lua_State.
    // Calls rule(sensorName, context) where context table contains ctx.fields
    // and optionally ctx.arrayField as a 1-indexed array.
    // matchedCheckIds: when non-empty, injected into the context as
    //   context.regex_matches (1-indexed Lua array of check ID strings).
    // Never throws. Returns {false} on timeout, error, or missing script.
    RaspLuaResult Run(const std::string&              ruleId,
                      const std::string&              sensorName,
                      const RaspLuaContext&           ctx,
                      int                             timeoutInstructions = 500000,
                      const std::vector<std::string>& matchedCheckIds     = {},
                      ScanExecutionContext*           exec                = nullptr);

#ifdef RASP_PCRE2_AVAILABLE
    // Tests text against each PCRE2 pattern in sequence.
    // Returns true on first match; sets matchedPatternOut to the matched pattern.
    // Patterns are compiled lazily and cached for the lifetime of the engine.
    // Thread-safe. Invalid patterns are skipped with a diagnostic log.
    bool MatchesAnyRegex(const std::vector<std::string>& patterns,
                         const std::string&               text,
                         std::string&                     matchedPatternOut,
                         ScanExecutionContext*            exec = nullptr) const;

    // Compile-or-fetch a PCRE2 pattern from the regex cache.
    // Public only so the static Lua C functions lua_pcre2_match / lua_pcre2_capture
    // (which retrieve the engine pointer via the Lua registry) can call it directly.
    // Returns nullptr if the pattern is invalid (error already logged).
    pcre2_real_code_8* GetOrCompilePcre2(const std::string& pattern) const;

    // Test/diagnostic seam for verifying the snapshot-local compiled regex cache.
    // Does not compile, evict, or otherwise mutate cache entries.
    size_t RegexCacheSizeForTesting() const;
#endif // RASP_PCRE2_AVAILABLE

    // Called by LuaPrint (a static free function in rasp_lua_engine.cpp that reads the
    // engine pointer from the Lua registry). Must be public so the free function can reach it.
    void Log(const char* msg) const;
    void LogWithSeverity(RaspDiagSeverity severity, const char* msg) const;

private:
    mutable std::mutex                           m_mutex;
    std::unordered_map<std::string, std::string> m_sources; // ruleId -> source or bytecode payload
    RaspLuaLogFn                                 m_logFn = nullptr;
    RaspLuaLeveledLogFn                          m_leveledLogFn = nullptr;

#ifdef RASP_PCRE2_AVAILABLE
    // Snapshot-local PCRE2 compiled-pattern cache. AMSI RuleSnapshot owns one
    // RaspLuaEngine instance, so compiled pcre2_code objects never cross reload
    // snapshot boundaries. GetOrCompilePcre2() attempts best-effort JIT during
    // compile; Layer A only reuses pcre2_code, not per-scan match context/data.
    mutable std::mutex                                           m_regexMutex;
    mutable std::unordered_map<std::string, pcre2_real_code_8*> m_regexCache;
#endif // RASP_PCRE2_AVAILABLE
};
