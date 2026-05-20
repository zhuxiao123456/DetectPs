#pragma once

#include "amsi_rule_provider.h"
#include "hostguard_amsi_ipc_adapter.h"

#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace hostguard_demo {

struct HostGuardPolicySnapshot {
    bool detectionEnabled = true;
    std::string policyVersion;
};

struct HostGuardModuleContext {
    amsi_ipc::IAmsiRuleProvider* ruleProvider = nullptr;
    std::shared_ptr<amsi_ipc::IAmsiRuleProvider> sharedRuleProvider;

    std::function<HostGuardPolicySnapshot()> loadPolicy;
    std::function<void(const HostGuardAmsiEventEnvelope& event)> eventBus;
    std::function<void(const HostGuardAmsiEventEnvelope& log)> dllDiagnosticLogBus;
    std::function<void(const std::string& rawStatus)> statusBus;
    std::function<void(const HostGuardAmsiAdapterDiag& diag)> diagLogger;

#if defined(HOSTGUARD_TESTING)
    std::function<bool(std::string& error)> beforeAdapterStartForTest;
#endif
};

struct HostGuardAmsiIpcModuleStatus {
    bool initialized = false;
    bool started = false;
    bool policyEnabled = true;
    bool desiredPolicyEnabled = true;
    bool lastPolicyBroadcastOk = false;
    bool lastReloadBroadcastOk = false;
    std::string policyVersion;
    std::string desiredPolicyVersion;
    std::string localRuleHash;
    std::string lastBroadcastRuleHash;
    std::string lastError;
    HostGuardAmsiIpcStatus adapter;
    HostGuardAmsiBroadcastResult lastReload;
    HostGuardAmsiBroadcastResult lastPolicyBroadcast;
    HostGuardAmsiBroadcastResult lastUnload;
};

struct HostGuardAmsiIpcModuleCommandResult {
    bool ok = false;
    std::string output;
    std::string error;
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
    std::string ExportStatusText() const;
    HostGuardAmsiIpcModuleCommandResult RunControlCommand(const std::string& command,
                                                          std::uint32_t timeoutMs);
    std::vector<HostGuardAmsiAdapterDiag> GetRecentAdapterDiag() const;

private:
    bool LoadRulesIntoAdapter(bool invalidateCache, std::string& error);
    bool BroadcastResultAccepted(bool broadcastOk) const;
    HostGuardModuleContext ContextSnapshot() const;
    amsi_ipc::IAmsiRuleProvider* RuleProviderFromContext(const HostGuardModuleContext& context) const;
    void RecordLastError(const std::string& error);

    mutable std::mutex mutex_;
    HostGuardAmsiIpcConfig config_;
    HostGuardModuleContext context_;
    HostGuardAmsiIpcAdapter adapter_;
    HostGuardAmsiIpcModuleStatus status_;
};

} // namespace hostguard_demo
