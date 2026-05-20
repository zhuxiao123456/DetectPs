#include "hostguard_amsi_ipc_module.h"

#include "amsi_rule_provider.h"
#include "hostguard_file_rule_provider.h"

#include <iomanip>
#include <sstream>
#include <utility>

namespace hostguard_demo {
namespace {

std::string HexUint64(std::uint64_t value)
{
    std::ostringstream out;
    out << std::hex << std::setw(16) << std::setfill('0') << value;
    return out.str();
}

std::string StableHash(const std::string& value)
{
    std::uint64_t hash = 1469598103934665603ULL;
    for (unsigned char ch : value) {
        hash ^= ch;
        hash *= 1099511628211ULL;
    }
    return HexUint64(hash);
}

HostGuardPolicySnapshot DefaultPolicy()
{
    return HostGuardPolicySnapshot{true, "hostguard-demo-policy-enabled"};
}

} // namespace

HostGuardAmsiIpcModule::HostGuardAmsiIpcModule() = default;

HostGuardAmsiIpcModule::~HostGuardAmsiIpcModule()
{
    UnInit();
}

bool HostGuardAmsiIpcModule::Init(const HostGuardAmsiIpcConfig& config,
                                  HostGuardModuleContext context,
                                  std::string& error)
{
    if (status_.initialized) {
        error = "module already initialized";
        return false;
    }
    if (!context.ruleProvider) {
        error = "module context requires ruleProvider";
        return false;
    }

    config_ = config;
    context_ = std::move(context);
    if (!context_.loadPolicy) {
        context_.loadPolicy = DefaultPolicy;
    }

    if (!adapter_.Init(config_, error)) {
        status_.lastError = error;
        return false;
    }

    adapter_.SetDetectionEventCallback([this](const HostGuardAmsiEventEnvelope& event) {
        if (context_.eventBus) {
            context_.eventBus(event);
        }
    });
    adapter_.SetDllDiagnosticLogCallback([this](const HostGuardAmsiEventEnvelope& log) {
        if (context_.dllDiagnosticLogBus) {
            context_.dllDiagnosticLogBus(log);
        } else if (context_.eventBus) {
            context_.eventBus(log);
        }
    });
    adapter_.SetStatusCallback([this](const std::string& rawStatus) {
        if (context_.statusBus) {
            context_.statusBus(rawStatus);
        }
    });
    adapter_.SetAdapterDiagCallback([this](const HostGuardAmsiAdapterDiag& diag) {
        if (context_.diagLogger) {
            context_.diagLogger(diag);
        }
    });

    status_.initialized = true;
    status_.started = false;
    status_.lastError.clear();
    return true;
}

bool HostGuardAmsiIpcModule::Start(std::string& error)
{
    if (!status_.initialized) {
        error = "module not initialized";
        status_.lastError = error;
        return false;
    }
    if (status_.started) {
        return true;
    }

    if (!LoadRulesIntoAdapter(false, error)) {
        status_.lastError = error;
        return false;
    }

    const HostGuardPolicySnapshot policy = context_.loadPolicy ? context_.loadPolicy() : DefaultPolicy();
    if (!adapter_.SetDetectionEnabled(policy.detectionEnabled, policy.policyVersion, error)) {
        status_.lastError = error;
        return false;
    }
    status_.policyEnabled = policy.detectionEnabled;
    status_.policyVersion = policy.policyVersion;

    if (!adapter_.Start(error)) {
        status_.lastError = error;
        adapter_.Stop();
        return false;
    }

    status_.started = true;
    status_.lastError.clear();
    return true;
}

void HostGuardAmsiIpcModule::Stop()
{
    adapter_.Stop();
    status_.started = false;
}

void HostGuardAmsiIpcModule::UnInit()
{
    Stop();
    status_.initialized = false;
    context_ = HostGuardModuleContext{};
}

bool HostGuardAmsiIpcModule::LoadRulesIntoAdapter(bool invalidateCache, std::string& error)
{
    if (!context_.ruleProvider) {
        error = "module context requires ruleProvider";
        return false;
    }
    if (invalidateCache) {
        context_.ruleProvider->InvalidateRuleCache();
    }

    amsi_ipc::AmsiRuleResponse allRules;
    amsi_ipc::AmsiRuleResponse amsiRules;
    if (!context_.ruleProvider->BuildRulesResponse("GET_ALL_RULES", allRules, error) ||
        !context_.ruleProvider->BuildRulesResponse("GET_RULES", amsiRules, error)) {
        return false;
    }

    const std::string ruleHash = StableHash(allRules.json + "\n" + amsiRules.json);
    return adapter_.UpdateRules(allRules.json,
                                amsiRules.json,
                                "hostguard-demo-" + ruleHash,
                                ruleHash,
                                error);
}

bool HostGuardAmsiIpcModule::BroadcastResultAccepted(bool broadcastOk) const
{
    return broadcastOk || !config_.enableRealIpc;
}

bool HostGuardAmsiIpcModule::ReloadRules(std::uint32_t timeoutMs, std::string& error)
{
    if (!LoadRulesIntoAdapter(true, error)) {
        status_.lastError = error;
        return false;
    }

    status_.lastReload = HostGuardAmsiBroadcastResult{};
    const bool broadcastOk = adapter_.Reload(timeoutMs, status_.lastReload);
    if (!BroadcastResultAccepted(broadcastOk)) {
        error = status_.lastReload.error;
        status_.lastError = error;
        return false;
    }
    status_.lastError.clear();
    return true;
}

bool HostGuardAmsiIpcModule::ApplyPolicy(bool enabled,
                                         const std::string& policyVersion,
                                         std::uint32_t timeoutMs,
                                         std::string& error)
{
    if (!adapter_.SetDetectionEnabled(enabled, policyVersion, error)) {
        status_.lastError = error;
        return false;
    }
    status_.policyEnabled = enabled;
    status_.policyVersion = policyVersion;

    status_.lastPolicyBroadcast = HostGuardAmsiBroadcastResult{};
    const bool broadcastOk = enabled ?
        adapter_.ResumeDetection(timeoutMs, status_.lastPolicyBroadcast) :
        adapter_.PauseDetection(timeoutMs, status_.lastPolicyBroadcast);
    if (!BroadcastResultAccepted(broadcastOk)) {
        error = status_.lastPolicyBroadcast.error;
        status_.lastError = error;
        return false;
    }
    status_.lastError.clear();
    return true;
}

bool HostGuardAmsiIpcModule::Unload(std::uint32_t timeoutMs, std::string& error)
{
    status_.lastUnload = HostGuardAmsiBroadcastResult{};
    const bool broadcastOk = adapter_.Unload(timeoutMs, status_.lastUnload);
    if (!BroadcastResultAccepted(broadcastOk)) {
        error = status_.lastUnload.error;
        status_.lastError = error;
        return false;
    }
    status_.lastError.clear();
    return true;
}

bool HostGuardAmsiIpcModule::InjectRawEventForTest(const std::string& rawJson)
{
    return adapter_.InjectRawEventForTest(rawJson);
}

bool HostGuardAmsiIpcModule::InjectStatusForTest(const std::string& rawJson)
{
    return adapter_.InjectStatusForTest(rawJson);
}

HostGuardAmsiIpcModuleStatus HostGuardAmsiIpcModule::GetStatus() const
{
    auto status = status_;
    status.adapter = adapter_.GetStatus();
    return status;
}

std::vector<HostGuardAmsiAdapterDiag> HostGuardAmsiIpcModule::GetRecentAdapterDiag() const
{
    return adapter_.GetRecentAdapterDiag();
}

} // namespace hostguard_demo
