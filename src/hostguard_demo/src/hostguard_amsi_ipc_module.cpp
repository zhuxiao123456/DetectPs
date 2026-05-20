#include "hostguard_amsi_ipc_module.h"

#include "amsi_rule_provider.h"

#include <exception>
#include <iomanip>
#include <mutex>
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
    return HostGuardPolicySnapshot{true, "hostguard-amsi-policy-enabled"};
}

const char* BoolText(bool value)
{
    return value ? "yes" : "no";
}

void AppendBroadcast(std::ostringstream& out,
                     const char* name,
                     const HostGuardAmsiBroadcastResult& result)
{
    out << name << ".command: " << result.command << "\n"
        << name << ".broadcastId: " << result.broadcastId << "\n"
        << name << ".delivered: " << result.delivered << "\n"
        << name << ".acked: " << result.acked << "\n"
        << name << ".failed: " << result.failed << "\n"
        << name << ".timeout: " << result.timeout << "\n"
        << name << ".error: " << result.error << "\n";
}

} // namespace

HostGuardAmsiIpcModule::HostGuardAmsiIpcModule() = default;

HostGuardAmsiIpcModule::~HostGuardAmsiIpcModule()
{
    UnInit();
}

HostGuardModuleContext HostGuardAmsiIpcModule::ContextSnapshot() const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return context_;
}

amsi_ipc::IAmsiRuleProvider* HostGuardAmsiIpcModule::RuleProviderFromContext(
    const HostGuardModuleContext& context) const
{
    return context.sharedRuleProvider ? context.sharedRuleProvider.get() : context.ruleProvider;
}

void HostGuardAmsiIpcModule::RecordLastError(const std::string& error)
{
    std::lock_guard<std::mutex> lock(mutex_);
    status_.lastError = error;
}

bool HostGuardAmsiIpcModule::Init(const HostGuardAmsiIpcConfig& config,
                                  HostGuardModuleContext context,
                                  std::string& error)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (status_.initialized) {
            error = "module already initialized";
            return false;
        }
        if (!context.ruleProvider && !context.sharedRuleProvider) {
            error = "module context requires ruleProvider";
            return false;
        }

        config_ = config;
        context_ = std::move(context);
        if (!context_.loadPolicy) {
            context_.loadPolicy = DefaultPolicy;
        }
    }

    if (!adapter_.Init(config, error)) {
        RecordLastError(error);
        return false;
    }

    adapter_.SetDetectionEventCallback([this](const HostGuardAmsiEventEnvelope& event) {
        const auto context = ContextSnapshot();
        if (context.eventBus) {
            try {
                context.eventBus(event);
            } catch (const std::exception& ex) {
                RecordLastError(std::string("eventBus callback failed: ") + ex.what());
            } catch (...) {
                RecordLastError("eventBus callback failed: unknown exception");
            }
        }
    });
    adapter_.SetDllDiagnosticLogCallback([this](const HostGuardAmsiEventEnvelope& log) {
        const auto context = ContextSnapshot();
        try {
            if (context.dllDiagnosticLogBus) {
                context.dllDiagnosticLogBus(log);
            } else if (context.eventBus) {
                context.eventBus(log);
            }
        } catch (const std::exception& ex) {
            RecordLastError(std::string("dllDiagnosticLogBus callback failed: ") + ex.what());
        } catch (...) {
            RecordLastError("dllDiagnosticLogBus callback failed: unknown exception");
        }
    });
    adapter_.SetStatusCallback([this](const std::string& rawStatus) {
        const auto context = ContextSnapshot();
        if (context.statusBus) {
            try {
                context.statusBus(rawStatus);
            } catch (const std::exception& ex) {
                RecordLastError(std::string("statusBus callback failed: ") + ex.what());
            } catch (...) {
                RecordLastError("statusBus callback failed: unknown exception");
            }
        }
    });
    adapter_.SetAdapterDiagCallback([this](const HostGuardAmsiAdapterDiag& diag) {
        const auto context = ContextSnapshot();
        if (context.diagLogger) {
            try {
                context.diagLogger(diag);
            } catch (const std::exception& ex) {
                RecordLastError(std::string("diagLogger callback failed: ") + ex.what());
            } catch (...) {
                RecordLastError("diagLogger callback failed: unknown exception");
            }
        }
    });

    std::lock_guard<std::mutex> lock(mutex_);
    status_.initialized = true;
    status_.started = false;
    status_.lastError.clear();
    return true;
}

bool HostGuardAmsiIpcModule::Start(std::string& error)
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!status_.initialized) {
            error = "module not initialized";
            status_.lastError = error;
            return false;
        }
        if (status_.started) {
            return true;
        }
    }

    if (!LoadRulesIntoAdapter(false, error)) {
        RecordLastError(error);
        return false;
    }

    const auto context = ContextSnapshot();
    HostGuardPolicySnapshot policy;
    try {
        policy = context.loadPolicy ? context.loadPolicy() : DefaultPolicy();
    } catch (const std::exception& ex) {
        error = std::string("loadPolicy failed: ") + ex.what();
        RecordLastError(error);
        return false;
    } catch (...) {
        error = "loadPolicy failed: unknown exception";
        RecordLastError(error);
        return false;
    }

    if (!adapter_.SetDetectionEnabled(policy.detectionEnabled, policy.policyVersion, error)) {
        RecordLastError(error);
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        status_.policyEnabled = policy.detectionEnabled;
        status_.desiredPolicyEnabled = policy.detectionEnabled;
        status_.policyVersion = policy.policyVersion;
        status_.desiredPolicyVersion = policy.policyVersion;
    }

#if defined(HOSTGUARD_TESTING)
    if (context.beforeAdapterStartForTest && !context.beforeAdapterStartForTest(error)) {
        RecordLastError(error);
        return false;
    }
#endif

    if (!adapter_.Start(error)) {
        RecordLastError(error);
        adapter_.Stop();
        return false;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    status_.started = true;
    status_.lastError.clear();
    return true;
}

void HostGuardAmsiIpcModule::Stop()
{
    adapter_.SetDetectionEventCallback(nullptr);
    adapter_.SetDllDiagnosticLogCallback(nullptr);
    adapter_.SetStatusCallback(nullptr);
    adapter_.SetAdapterDiagCallback(nullptr);
    adapter_.Stop();
    std::lock_guard<std::mutex> lock(mutex_);
    status_.started = false;
}

void HostGuardAmsiIpcModule::UnInit()
{
    Stop();
    std::lock_guard<std::mutex> lock(mutex_);
    status_.initialized = false;
    context_ = HostGuardModuleContext{};
}

bool HostGuardAmsiIpcModule::LoadRulesIntoAdapter(bool invalidateCache, std::string& error)
{
    const auto context = ContextSnapshot();
    auto* ruleProvider = RuleProviderFromContext(context);
    if (!ruleProvider) {
        error = "module context requires ruleProvider";
        return false;
    }
    if (invalidateCache) {
        ruleProvider->InvalidateRuleCache();
    }

    amsi_ipc::AmsiRuleResponse allRules;
    amsi_ipc::AmsiRuleResponse amsiRules;
    if (!ruleProvider->BuildRulesResponse("GET_ALL_RULES", allRules, error) ||
        !ruleProvider->BuildRulesResponse("GET_RULES", amsiRules, error)) {
        return false;
    }

    const std::string ruleHash = StableHash(allRules.json + "\n" + amsiRules.json);
    if (!adapter_.UpdateRules(allRules.json,
                              amsiRules.json,
                              "hostguard-amsi-rule-" + ruleHash,
                              ruleHash,
                              error)) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    status_.localRuleHash = ruleHash;
    return true;
}

bool HostGuardAmsiIpcModule::BroadcastResultAccepted(bool broadcastOk) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    return broadcastOk || !config_.enableRealIpc;
}

bool HostGuardAmsiIpcModule::ReloadRules(std::uint32_t timeoutMs, std::string& error)
{
    if (!LoadRulesIntoAdapter(true, error)) {
        RecordLastError(error);
        return false;
    }

    HostGuardAmsiBroadcastResult result;
    const bool broadcastOk = adapter_.Reload(timeoutMs, result);
    const bool accepted = BroadcastResultAccepted(broadcastOk);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        status_.lastReload = result;
        status_.lastReloadBroadcastOk = accepted;
        if (status_.lastReloadBroadcastOk) {
            status_.lastBroadcastRuleHash = status_.localRuleHash;
        }
    }
    if (!accepted) {
        error = result.error;
        RecordLastError(error);
        return false;
    }
    RecordLastError("");
    return true;
}

bool HostGuardAmsiIpcModule::ApplyPolicy(bool enabled,
                                         const std::string& policyVersion,
                                         std::uint32_t timeoutMs,
                                         std::string& error)
{
    if (!adapter_.SetDetectionEnabled(enabled, policyVersion, error)) {
        RecordLastError(error);
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        status_.policyEnabled = enabled;
        status_.desiredPolicyEnabled = enabled;
        status_.policyVersion = policyVersion;
        status_.desiredPolicyVersion = policyVersion;
    }

    HostGuardAmsiBroadcastResult result;
    const bool broadcastOk = enabled ?
        adapter_.ResumeDetection(timeoutMs, result) :
        adapter_.PauseDetection(timeoutMs, result);
    const bool accepted = BroadcastResultAccepted(broadcastOk);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        status_.lastPolicyBroadcast = result;
        status_.lastPolicyBroadcastOk = accepted;
    }
    if (!accepted) {
        error = result.error;
        RecordLastError(error);
        return false;
    }
    RecordLastError("");
    return true;
}

bool HostGuardAmsiIpcModule::Unload(std::uint32_t timeoutMs, std::string& error)
{
    HostGuardAmsiBroadcastResult result;
    const bool broadcastOk = adapter_.Unload(timeoutMs, result);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        status_.lastUnload = result;
    }
    if (!BroadcastResultAccepted(broadcastOk)) {
        error = result.error;
        RecordLastError(error);
        return false;
    }
    RecordLastError("");
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
    HostGuardAmsiIpcModuleStatus status;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        status = status_;
    }
    status.adapter = adapter_.GetStatus();
    return status;
}

std::string HostGuardAmsiIpcModule::ExportStatusText() const
{
    const auto status = GetStatus();
    std::ostringstream out;
    out << "module.initialized: " << BoolText(status.initialized) << "\n"
        << "module.started: " << BoolText(status.started) << "\n"
        << "module.policyEnabled: " << BoolText(status.policyEnabled) << "\n"
        << "module.desiredPolicyEnabled: " << BoolText(status.desiredPolicyEnabled) << "\n"
        << "module.lastPolicyBroadcastOk: " << BoolText(status.lastPolicyBroadcastOk) << "\n"
        << "module.lastReloadBroadcastOk: " << BoolText(status.lastReloadBroadcastOk) << "\n"
        << "module.policyVersion: " << status.policyVersion << "\n"
        << "module.desiredPolicyVersion: " << status.desiredPolicyVersion << "\n"
        << "module.localRuleHash: " << status.localRuleHash << "\n"
        << "module.lastBroadcastRuleHash: " << status.lastBroadcastRuleHash << "\n"
        << "module.lastError: " << status.lastError << "\n"
        << "adapter.initialized: " << BoolText(status.adapter.initialized) << "\n"
        << "adapter.started: " << BoolText(status.adapter.started) << "\n"
        << "adapter.lifecycleState: " << status.adapter.lifecycleState << "\n"
        << "adapter.productionPipes: " << BoolText(status.adapter.productionPipes) << "\n"
        << "adapter.detectionEnabled: " << BoolText(status.adapter.detectionEnabled) << "\n"
        << "adapter.lastRuleVersion: " << status.adapter.lastRuleVersion << "\n"
        << "adapter.lastRuleHash: " << status.adapter.lastRuleHash << "\n"
        << "adapter.lastPolicyVersion: " << status.adapter.lastPolicyVersion << "\n"
        << "adapter.lastError: " << status.adapter.lastError << "\n"
        << "adapter.ruleRequests: " << status.adapter.ruleRequests << "\n"
        << "adapter.ruleRequestUnsupported: " << status.adapter.ruleRequestUnsupported << "\n"
        << "adapter.eventReceived: " << status.adapter.eventReceived << "\n"
        << "adapter.detectionEventReceived: " << status.adapter.detectionEventReceived << "\n"
        << "adapter.dllDiagnosticLogReceived: " << status.adapter.dllDiagnosticLogReceived << "\n"
        << "adapter.drainAckReceived: " << status.adapter.drainAckReceived << "\n"
        << "adapter.drainAckCorrelated: " << status.adapter.drainAckCorrelated << "\n"
        << "adapter.drainAckUncorrelated: " << status.adapter.drainAckUncorrelated << "\n"
        << "adapter.unknownEventReceived: " << status.adapter.unknownEventReceived << "\n"
        << "adapter.statusReceived: " << status.adapter.statusReceived << "\n"
        << "adapter.detectionEventDropped: " << status.adapter.detectionEventDropped << "\n"
        << "adapter.dllDiagnosticLogDropped: " << status.adapter.dllDiagnosticLogDropped << "\n"
        << "adapter.statusDropped: " << status.adapter.statusDropped << "\n";
    AppendBroadcast(out, "module.lastReload", status.lastReload);
    AppendBroadcast(out, "module.lastPolicyBroadcast", status.lastPolicyBroadcast);
    AppendBroadcast(out, "module.lastUnload", status.lastUnload);
    return out.str();
}

HostGuardAmsiIpcModuleCommandResult HostGuardAmsiIpcModule::RunControlCommand(const std::string& command,
                                                                              std::uint32_t timeoutMs)
{
    HostGuardAmsiIpcModuleCommandResult result;
    if (command == "status") {
        result.ok = true;
        result.output = ExportStatusText();
        return result;
    }
    if (command == "dump-diag") {
        result.ok = true;
        std::ostringstream out;
        const auto entries = GetRecentAdapterDiag();
        for (const auto& entry : entries) {
            out << entry.timestamp << " " << entry.level << " ["
                << entry.component << "] " << entry.message << "\n";
        }
        if (entries.empty()) {
            out << "(none)\n";
        }
        result.output = out.str();
        return result;
    }

    std::string error;
    if (command == "reload-rules") {
        result.ok = ReloadRules(timeoutMs, error);
    } else if (command == "pause-detection") {
        result.ok = ApplyPolicy(false, "hostguard-amsi-policy-manual-disabled", timeoutMs, error);
    } else if (command == "resume-detection") {
        result.ok = ApplyPolicy(true, "hostguard-amsi-policy-manual-enabled", timeoutMs, error);
    } else {
        error = "unsupported module control command: " + command;
        result.ok = false;
    }

    result.error = error;
    result.output = result.ok ? ExportStatusText() : std::string{};
    return result;
}

std::vector<HostGuardAmsiAdapterDiag> HostGuardAmsiIpcModule::GetRecentAdapterDiag() const
{
    return adapter_.GetRecentAdapterDiag();
}

} // namespace hostguard_demo
