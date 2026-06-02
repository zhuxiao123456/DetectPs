#include "hostguard_file_rule_provider.h"

#include "nlohmann/json.hpp"

#include <cstring>
#include <fstream>
#include <mutex>
#include <sstream>
#include <utility>

using json = nlohmann::json;

HostGuardFileRuleProvider::HostGuardFileRuleProvider(std::string rulesPath)
    : rulesPath_(std::move(rulesPath))
{
}

bool HostGuardFileRuleProvider::BuildRulesResponse(const std::string& command,
                                                   amsi_ipc::AmsiRuleResponse& out,
                                                   std::string& error)
{
    if (_stricmp(command.c_str(), "GET_RULES") == 0) {
        out.json = BuildStateEnvelope(GetAmsiRulesJson());
        return true;
    }
    if (_stricmp(command.c_str(), "GET_ALL_RULES") == 0) {
        out.json = BuildStateEnvelope(GetAllRulesJson());
        return true;
    }

    error = "unknown command: " + command;
    return false;
}

void HostGuardFileRuleProvider::InvalidateRuleCache()
{
    std::unique_lock<std::shared_mutex> guard(lock_);
    cachedAllRules_.clear();
    cachedAmsiRules_.clear();
}

bool HostGuardFileRuleProvider::cache_ready() const
{
    std::shared_lock<std::shared_mutex> guard(lock_);
    return !cachedAllRules_.empty() || !cachedAmsiRules_.empty();
}

bool HostGuardFileRuleProvider::SetControlState(const std::string& state, std::string& error)
{
    if (state != "running" && state != "unload") {
        error = "state must be running or unload";
        return false;
    }

    std::unique_lock<std::shared_mutex> guard(lock_);
    if (controlState_ != state) {
        controlState_ = state;
        ++stateRevision_;
    }
    return true;
}

std::string HostGuardFileRuleProvider::control_state() const
{
    std::shared_lock<std::shared_mutex> guard(lock_);
    return controlState_;
}

void HostGuardFileRuleProvider::SetRequiredDllHash(std::string hash)
{
    std::unique_lock<std::shared_mutex> guard(lock_);
    if (requiredDllHash_ != hash) {
        requiredDllHash_ = std::move(hash);
        ++stateRevision_;
    }
}

std::string HostGuardFileRuleProvider::required_dll_hash() const
{
    std::shared_lock<std::shared_mutex> guard(lock_);
    return requiredDllHash_;
}

std::string HostGuardFileRuleProvider::GetAllRulesJson()
{
    {
        std::shared_lock<std::shared_mutex> guard(lock_);
        if (!cachedAllRules_.empty()) {
            return cachedAllRules_;
        }
    }

    const std::string built = BuildAllRulesJson();
    std::unique_lock<std::shared_mutex> guard(lock_);
    if (cachedAllRules_.empty()) {
        cachedAllRules_ = built;
    }
    return cachedAllRules_;
}

std::string HostGuardFileRuleProvider::GetAmsiRulesJson()
{
    {
        std::shared_lock<std::shared_mutex> guard(lock_);
        if (!cachedAmsiRules_.empty()) {
            return cachedAmsiRules_;
        }
    }

    const std::string allRules = GetAllRulesJson();
    const std::string built = BuildAmsiRulesJson(allRules);
    std::unique_lock<std::shared_mutex> guard(lock_);
    if (cachedAmsiRules_.empty()) {
        cachedAmsiRules_ = built;
    }
    return cachedAmsiRules_;
}

std::string HostGuardFileRuleProvider::BuildAllRulesJson() const
{
    std::ifstream input(rulesPath_, std::ios::binary);
    if (!input.is_open()) {
        return "[]";
    }

    try {
        json root;
        input >> root;
        return root.dump();
    } catch (...) {
        return "[]";
    }
}

std::string HostGuardFileRuleProvider::BuildAmsiRulesJson(const std::string& allRulesJson) const
{
    try {
        const json root = json::parse(allRulesJson);
        if (!root.is_object() || !root.contains("rules") || !root["rules"].is_array()) {
            return "[]";
        }

        json result = json::array();
        for (const auto& rule : root["rules"]) {
            if (!rule.is_object() || !rule.contains("sensor") || !rule["sensor"].is_string()) {
                continue;
            }
            if (rule["sensor"].get<std::string>() == "AmsiProvider") {
                result.push_back(rule);
            }
        }
        return result.dump();
    } catch (...) {
        return "[]";
    }
}

std::string HostGuardFileRuleProvider::BuildStateEnvelope(const std::string& rulesJson) const
{
    std::string state;
    std::string requiredDllHash;
    std::uint64_t revision = 0;
    {
        std::shared_lock<std::shared_mutex> guard(lock_);
        state = controlState_;
        requiredDllHash = requiredDllHash_;
        revision = stateRevision_;
    }

    json rules = json::object();
    try {
        rules = json::parse(rulesJson);
    } catch (...) {
        rules = json::object();
    }

    const std::string ruleVersion = RuleVersionFromJson(rulesJson);
    std::ostringstream stateVersion;
    stateVersion << state << "-" << revision;

    json envelope;
    envelope["desiredRuntimeState"] = (state == "unload") ? "unloading" : "running";
    envelope["state"] = state;
    envelope["stateVersion"] = stateVersion.str();
    envelope["ruleVersion"] = ruleVersion;
    envelope["requiredDllHash"] = requiredDllHash;
    envelope["rules"] = (state == "running") ? rules : json::object();
    return envelope.dump();
}

std::string HostGuardFileRuleProvider::RuleVersionFromJson(const std::string& rulesJson) const
{
    try {
        const json root = json::parse(rulesJson);
        if (root.is_object() && root.contains("version") && root["version"].is_string()) {
            return root["version"].get<std::string>();
        }
    } catch (...) {
    }
    return "hostguard-demo-rules";
}
