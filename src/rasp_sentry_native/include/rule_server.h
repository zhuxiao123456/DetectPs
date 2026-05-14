#pragma once
// rule_server.h - 8-thread named pipe server on \\.\pipe\amsi_detect_rules.
// Responds to GET_RULES and GET_ALL_RULES commands with assembled JSON.
// Replaces all custom C# JSON methods with nlohmann/json DOM operations.
// nlohmann/json is only included in rule_server.cpp — not exposed here.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <atomic>
#include <string>

class RuleServer
{
public:
    static constexpr const wchar_t* kPipeName   = L"amsi_detect_rules";
    static constexpr int            kThreadCount = 8;

    explicit RuleServer(std::string rulesPath);
    ~RuleServer();

    void Start();
    void Stop();
    void InvalidateCache();     // called by ConfigWatcher on file change

private:
    std::string       m_rulesPath;
    std::atomic<bool> m_running{false};
    HANDLE            m_threads[kThreadCount];
    CRITICAL_SECTION  m_cacheLock;
    std::string       m_cachedAssembled;    // "" = cache miss
    std::string       m_cachedAmsiRules;    // "" = cache miss

    static DWORD WINAPI ThreadProc(LPVOID param);
    void ServerLoop();

    const std::string& GetAssembledJson();
    const std::string& GetAmsiRulesJson();

    // JSON assembly — delegates to static helpers in rule_server.cpp
    std::string BuildAssembledJson();
    std::string FilterAmsiProviderRules(const std::string& assembledJson);
};
