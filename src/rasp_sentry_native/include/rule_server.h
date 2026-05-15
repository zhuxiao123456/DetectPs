#pragma once
// rule_server.h - 8-thread named pipe server on \\.\pipe\amsi_detect_rules.
// Responds to GET_RULES with AMSI-filtered JSON and GET_ALL_RULES with assembled JSON.
// Replaces all custom C# JSON methods with nlohmann/json DOM operations.
// nlohmann/json is only included in rule_server.cpp — not exposed here.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>

#include "amsi_pipe_names.h"
#include "amsi_rule_channel.h"
#include "amsi_rule_provider.h"
#include "named_pipe_server_pool.h"

class RuleServer : public amsi_ipc::IAmsiRuleProvider
{
public:
    static constexpr const wchar_t* kPipeName   = L"amsi_detect_rules";
    static constexpr int            kThreadCount = 8;

    explicit RuleServer(std::string rulesPath);
    ~RuleServer();

    void Start();
    void Stop();
    void InvalidateCache();     // called by ConfigWatcher on file change
    void InvalidateRuleCache() override;

    bool BuildRulesResponse(const std::string& command,
                            amsi_ipc::AmsiRuleResponse& out,
                            std::string& error) override;

private:
    std::string       m_rulesPath;
    bool              m_started = false;
    CRITICAL_SECTION  m_cacheLock;
    std::string       m_cachedAssembled;    // "" = cache miss
    std::string       m_cachedAmsiRules;    // "" = cache miss

    amsi_ipc::AmsiRuleChannel m_ruleChannel;
    amsi_ipc::NamedPipeServerPool m_rulePipePool;

    const std::string& GetAssembledJson();
    const std::string& GetAmsiRulesJson();

    // JSON assembly — delegates to static helpers in rule_server.cpp
    std::string BuildAssembledJson();
    std::string FilterAmsiProviderRules(const std::string& assembledJson);
};
