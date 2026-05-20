#pragma once

#include "hostguard_amsi_ipc_adapter.h"

#include <functional>
#include <string>
#include <vector>

class HostGuardFileRuleProvider;

namespace hostguard_demo {

struct HostGuardPolicySnapshot {
    bool detectionEnabled = true;
    std::string policyVersion;
};

struct HostGuardModuleContext {
    HostGuardFileRuleProvider* ruleProvider = nullptr;

    std::function<HostGuardPolicySnapshot()> loadPolicy;
    std::function<void(const HostGuardAmsiEventEnvelope& event)> eventBus;
    std::function<void(const HostGuardAmsiEventEnvelope& log)> dllDiagnosticLogBus;
    std::function<void(const std::string& rawStatus)> statusBus;
    std::function<void(const HostGuardAmsiAdapterDiag& diag)> diagLogger;
};

struct HostGuardAmsiIpcModuleStatus {
    bool initialized = false;
    bool started = false;
    bool policyEnabled = true;
    std::string policyVersion;
    std::string lastError;
    HostGuardAmsiIpcStatus adapter;
    HostGuardAmsiBroadcastResult lastReload;
    HostGuardAmsiBroadcastResult lastPolicyBroadcast;
    HostGuardAmsiBroadcastResult lastUnload;
};

class HostGuardAmsiIpcModule {
public:
    HostGuardAmsiIpcModule();
    ~HostGuardAmsiIpcModule();

    HostGuardAmsiIpcModule(const HostGuardAmsiIpcModule&) = delete;
    HostGuardAmsiIpcModule& operator=(const HostGuardAmsiIpcModule&) = delete;

    bool Init(const HostGuardAmsiIpcConfig& config,
              HostGuardModuleContext context,
              std::string& error);
    bool Start(std::string& error);
    void Stop();
    void UnInit();

    bool ReloadRules(std::uint32_t timeoutMs, std::string& error);
    bool ApplyPolicy(bool enabled,
                     const std::string& policyVersion,
                     std::uint32_t timeoutMs,
                     std::string& error);
    bool Unload(std::uint32_t timeoutMs, std::string& error);

    bool InjectRawEventForTest(const std::string& rawJson);
    bool InjectStatusForTest(const std::string& rawJson);

    HostGuardAmsiIpcModuleStatus GetStatus() const;
    std::vector<HostGuardAmsiAdapterDiag> GetRecentAdapterDiag() const;

private:
    bool LoadRulesIntoAdapter(bool invalidateCache, std::string& error);
    bool BroadcastResultAccepted(bool broadcastOk) const;

    HostGuardAmsiIpcConfig config_;
    HostGuardModuleContext context_;
    HostGuardAmsiIpcAdapter adapter_;
    HostGuardAmsiIpcModuleStatus status_;
};

} // namespace hostguard_demo
