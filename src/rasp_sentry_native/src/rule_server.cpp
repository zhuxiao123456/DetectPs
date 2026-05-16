#include "rule_server.h"

#include "sentry_log.h"

RuleServer::RuleServer(std::string rulesPath)
    : m_ownedProvider(new DemoFileRuleProvider(std::move(rulesPath))),
      m_provider(m_ownedProvider.get()),
      m_ruleChannel(*this),
      m_rulePipePool(amsi_ipc::kRulesPipeName, kThreadCount, m_ruleChannel)
{
}

RuleServer::RuleServer(amsi_ipc::IAmsiRuleProvider& provider)
    : m_provider(&provider),
      m_ruleChannel(*this),
      m_rulePipePool(amsi_ipc::kRulesPipeName, kThreadCount, m_ruleChannel)
{
}

RuleServer::~RuleServer()
{
    Stop();
}

void RuleServer::Start()
{
    if (m_started) {
        return;
    }
    m_started = true;
    if (!m_rulePipePool.Start()) {
        SentryLog_Error("RuleServer", "Failed to start one or more rule pipe worker thread(s)");
    }
}

void RuleServer::Stop()
{
    if (!m_started) {
        return;
    }
    m_rulePipePool.Stop();
    m_started = false;
}

void RuleServer::InvalidateCache()
{
    InvalidateRuleCache();
}

void RuleServer::InvalidateRuleCache()
{
    if (m_provider) {
        m_provider->InvalidateRuleCache();
    }
}

amsi_ipc::IAmsiRuleProvider* RuleServer::RuleProvider()
{
    return m_provider;
}

bool RuleServer::BuildRulesResponse(const std::string& command,
                                    amsi_ipc::AmsiRuleResponse& out,
                                    std::string& error)
{
    if (!m_provider) {
        error = "rule provider unavailable";
        return false;
    }
    return m_provider->BuildRulesResponse(command, out, error);
}
