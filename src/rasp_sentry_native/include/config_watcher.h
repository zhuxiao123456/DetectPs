#pragma once
// config_watcher.h — Watches rasp_rules.json and rules/*.lua for changes.
// On change: 1-second debounce → invalidate RuleServer cache →
// broadcast 0x01 reload byte to \\.\pipe\rasp_sentry_config.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <atomic>
#include <string>

class RuleServer;   // forward — avoid circular include

class ConfigWatcher
{
public:
    static constexpr const wchar_t* kConfigPipeName  = L"\\\\.\\pipe\\rasp_sentry_config";
    static constexpr int            kMaxListeners     = 32;
    static constexpr DWORD          kDebounceMs       = 1000;
    static constexpr DWORD          kBroadcastTimeout = 500;

    ConfigWatcher(std::string rulesPath, RuleServer* ruleServer);
    ~ConfigWatcher();

    void Start();
    void Stop();

private:
    std::string       m_rulesPath;
    std::string       m_rulesDir;
    RuleServer*       m_ruleServer;
    std::atomic<bool> m_running{false};

    HANDLE            m_rulesFileThread  = INVALID_HANDLE_VALUE;
    HANDLE            m_luaDirThread     = INVALID_HANDLE_VALUE;
    HANDLE            m_stopEvent        = nullptr;

    CRITICAL_SECTION  m_debounceLock;
    HANDLE            m_debounceTimer    = nullptr;

    struct WatchParams { ConfigWatcher* self; bool recursive; std::wstring dir; std::wstring filter; };

    static DWORD WINAPI WatchRulesFileProc(LPVOID param);
    static DWORD WINAPI WatchLuaDirProc   (LPVOID param);
    void WatchDirectory(const std::wstring& dir, const wchar_t* filter, bool recursive);
    void OnChanged();

    static VOID CALLBACK DebounceCallback(PVOID param, BOOLEAN fired);
    void FireDebounced();
    void BroadcastReload();

    static std::string DirOf(const std::string& filePath);
};
