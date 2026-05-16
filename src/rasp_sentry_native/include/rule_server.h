#pragma once
// rule_server.h - compatibility wrapper for the amsi_detect_rules pipe.
// Rule JSON assembly is owned by DemoFileRuleProvider; this class keeps the
// existing pipe lifecycle stable during the HostGuard migration.

#include <memory>
#include <string>

#include "amsi_pipe_names.h"
#include "amsi_rule_channel.h"
#include "amsi_rule_provider.h"
#include "demo_file_rule_provider.h"
#include "named_pipe_server_pool.h"

class RuleServer : public amsi_ipc::IAmsiRuleProvider
{
public:
    static constexpr const wchar_t* kPipeName = L"amsi_detect_rules";
    static constexpr int kThreadCount = 8;

    explicit RuleServer(std::string rulesPath);
    RuleServer(std::string rulesPath, std::wstring pipeName);
    explicit RuleServer(amsi_ipc::IAmsiRuleProvider& provider);
    RuleServer(amsi_ipc::IAmsiRuleProvider& provider, std::wstring pipeName);
    ~RuleServer();

    void Start();
    void Stop();
    void InvalidateCache();
    void InvalidateRuleCache() override;
    amsi_ipc::IAmsiRuleProvider* RuleProvider();

    bool BuildRulesResponse(const std::string& command,
                            amsi_ipc::AmsiRuleResponse& out,
                            std::string& error) override;

private:
    bool m_started = false;
    std::unique_ptr<DemoFileRuleProvider> m_ownedProvider;
    amsi_ipc::IAmsiRuleProvider* m_provider = nullptr;

    amsi_ipc::AmsiRuleChannel m_ruleChannel;
    amsi_ipc::NamedPipeServerPool m_rulePipePool;
};
