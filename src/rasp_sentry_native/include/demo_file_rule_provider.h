#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>

#include "amsi_rule_provider.h"

class DemoFileRuleProvider : public amsi_ipc::IAmsiRuleProvider
{
public:
    explicit DemoFileRuleProvider(std::string rulesPath);
    ~DemoFileRuleProvider();

    DemoFileRuleProvider(const DemoFileRuleProvider&) = delete;
    DemoFileRuleProvider& operator=(const DemoFileRuleProvider&) = delete;

    bool BuildRulesResponse(const std::string& command,
                            amsi_ipc::AmsiRuleResponse& out,
                            std::string& error) override;

    void InvalidateRuleCache() override;

private:
    const std::string& GetAssembledJson();
    const std::string& GetAmsiRulesJson();

    std::string BuildAssembledJson();
    std::string FilterAmsiProviderRules(const std::string& assembledJson);

    std::string rulesPath_;
    CRITICAL_SECTION cacheLock_;
    std::string cachedAssembled_;
    std::string cachedAmsiRules_;
};
