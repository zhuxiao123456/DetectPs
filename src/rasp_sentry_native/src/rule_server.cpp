#include "rule_server.h"

#include "sentry_log.h"

namespace {

constexpr DWORD kRulePipeOutBufferBytes = 512 * 1024;
constexpr DWORD kRulePipeInBufferBytes = 256;

} // namespace

RuleServer::RuleServer(std::string rulesPath)
    : RuleServer(std::move(rulesPath), amsi_ipc::kRulesPipeName)
{
}

RuleServer::RuleServer(std::string rulesPath, std::wstring pipeName, int threadCount)
    : m_ownedProvider(new DemoFileRuleProvider(std::move(rulesPath))),
      m_provider(m_ownedProvider.get()),
      m_threadCount(threadCount),
      m_ruleChannel(*this),
      m_rulePipePool(std::move(pipeName),
                     threadCount,
                     m_ruleChannel,
                     kRulePipeOutBufferBytes,
                     kRulePipeInBufferBytes)
{
}

RuleServer::RuleServer(amsi_ipc::IAmsiRuleProvider& provider)
    : RuleServer(provider, amsi_ipc::kRulesPipeName)
{
}

RuleServer::RuleServer(amsi_ipc::IAmsiRuleProvider& provider, std::wstring pipeName, int threadCount)
    : m_provider(&provider),
      m_threadCount(threadCount),
      m_ruleChannel(*this),
      m_rulePipePool(std::move(pipeName),
                     threadCount,
                     m_ruleChannel,
                     kRulePipeOutBufferBytes,
                     kRulePipeInBufferBytes)
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
