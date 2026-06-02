#pragma once

#include "amsi_rule_provider.h"

#include <cstdint>
#include <shared_mutex>
#include <string>

class HostGuardFileRuleProvider final : public amsi_ipc::IAmsiRuleProvider {
public:
    explicit HostGuardFileRuleProvider(std::string rulesPath);

    bool BuildRulesResponse(const std::string& command,
                            amsi_ipc::AmsiRuleResponse& out,
                            std::string& error) override;

    void InvalidateRuleCache() override;

    bool cache_ready() const;
    bool SetControlState(const std::string& state, std::string& error);
    std::string control_state() const;
    void SetRequiredDllHash(std::string hash);
    std::string required_dll_hash() const;

private:
    std::string GetAllRulesJson();
    std::string GetAmsiRulesJson();
    std::string BuildAllRulesJson() const;
    std::string BuildAmsiRulesJson(const std::string& allRulesJson) const;
    std::string BuildStateEnvelope(const std::string& rulesJson) const;
    std::string RuleVersionFromJson(const std::string& rulesJson) const;

    std::string rulesPath_;
    mutable std::shared_mutex lock_;
    std::string cachedAllRules_;
    std::string cachedAmsiRules_;
    std::string controlState_ = "running";
    std::string requiredDllHash_;
    std::uint64_t stateRevision_ = 1;
};
