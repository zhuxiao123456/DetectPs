#include "hostguard_demo_app.h"

#include "amsi_ipc_host.h"
#include "hostguard_file_rule_provider.h"
#include "hostguard_jsonl_control_status_sink.h"
#include "hostguard_jsonl_event_sink.h"
#include "hostguard_paths.h"
#include "sentry_log.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <iostream>

namespace {

std::string NarrowAscii(const std::wstring& value)
{
    std::string out;
    out.reserve(value.size());
    for (wchar_t ch : value) {
        out.push_back(static_cast<char>(ch));
    }
    return out;
}

bool PipeServerExists(const std::wstring& pipeName)
{
    if (WaitNamedPipeW(pipeName.c_str(), 0)) {
        return true;
    }

    const DWORD error = GetLastError();
    return error == ERROR_PIPE_BUSY || error == ERROR_SEM_TIMEOUT;
}

} // namespace

const char* HostGuardPipeModeName(HostGuardPipeMode mode)
{
    return mode == HostGuardPipeMode::Production ? "production" : "demo";
}

void ApplyHostGuardPipeMode(HostGuardDemoOptions& options, HostGuardPipeMode mode)
{
    options.pipeMode = mode;
    options.strictHostGuardMode = true;
    options.enableDemoConfigWatcher = false;
    options.enableDemoStagingWatcher = false;

    if (mode == HostGuardPipeMode::Production) {
        options.amsiIpc.useProductionPipes = true;
        options.rulesPipeName = LR"(\\.\pipe\amsi_detect_rules)";
        options.eventsPipeName = LR"(\\.\pipe\amsi_detect_events)";
        options.controlStatusPipeName = LR"(\\.\pipe\amsi_detect_control_status)";
        options.configPipeName = LR"(\\.\pipe\amsi_detect_config)";
        return;
    }

    options.amsiIpc.useProductionPipes = false;
    options.rulesPipeName = LR"(\\.\pipe\amsi_detect_rules_demo)";
    options.eventsPipeName = LR"(\\.\pipe\amsi_detect_events_demo)";
    options.controlStatusPipeName = LR"(\\.\pipe\amsi_detect_control_status_demo)";
    options.configPipeName = LR"(\\.\pipe\amsi_detect_config_demo)";
}

HostGuardDemoApp::HostGuardDemoApp(HostGuardDemoOptions options)
    : options_(std::move(options))
{
}

HostGuardDemoApp::~HostGuardDemoApp()
{
    Stop();
}

bool HostGuardDemoApp::Start()
{
    if (started_) {
        return true;
    }
    startError_.clear();

    if (PipeServerExists(options_.rulesPipeName)) {
        startError_ = std::string(HostGuardPipeModeName(options_.pipeMode)) +
                      " rules pipe is already served: " + NarrowAscii(options_.rulesPipeName);
        return false;
    }
    if (PipeServerExists(options_.eventsPipeName)) {
        startError_ = std::string(HostGuardPipeModeName(options_.pipeMode)) +
                      " events pipe is already served: " + NarrowAscii(options_.eventsPipeName);
        return false;
    }
    if (PipeServerExists(options_.controlStatusPipeName)) {
        startError_ = std::string(HostGuardPipeModeName(options_.pipeMode)) +
                      " control status pipe is already served: " +
                      NarrowAscii(options_.controlStatusPipeName);
        return false;
    }
    // Legacy config/control is DLL-listener based: loaded DLL instances create
    // amsi_detect_config and the Host connects to broadcast 0x01/0x02/0x03/0x04.
    // Do not treat an existing config pipe as a competing Host server.

    hostguard_demo::EnsureDirectory(options_.logDir);

    ruleProvider_.reset(new HostGuardFileRuleProvider(options_.rulesPath));
    eventSink_.reset(new HostGuardJsonlEventSink(options_.logDir));
    controlStatusSink_.reset(new HostGuardJsonlControlStatusSink(options_.logDir));

    if (options_.amsiIpc.enabled) {
        amsiIpcModule_.reset(new hostguard_demo::HostGuardAmsiIpcModule());

        hostguard_demo::HostGuardAmsiIpcConfig adapterConfig;
        adapterConfig.enableRealIpc = options_.amsiIpc.enableRealIpc;
        adapterConfig.useProductionPipes = options_.amsiIpc.useProductionPipes;
        adapterConfig.rulesPipeName = options_.rulesPipeName;
        adapterConfig.eventsPipeName = options_.eventsPipeName;
        adapterConfig.controlStatusPipeName = options_.controlStatusPipeName;
        adapterConfig.configPipeName = options_.configPipeName;

        hostguard_demo::HostGuardModuleContext context;
        context.ruleProvider = ruleProvider_.get();
        context.loadPolicy = []() {
            return hostguard_demo::HostGuardPolicySnapshot{true, "hostguard-amsi-policy-enabled"};
        };
        context.eventBus = [this](const hostguard_demo::HostGuardAmsiEventEnvelope& event) {
            if (eventSink_) {
                eventSink_->OnEventLine(amsi_ipc::AmsiEventLine{event.rawJson});
            }
        };
        context.dllDiagnosticLogBus = [this](const hostguard_demo::HostGuardAmsiEventEnvelope& log) {
            if (eventSink_) {
                eventSink_->OnEventLine(amsi_ipc::AmsiEventLine{log.rawJson});
            }
        };
        context.statusBus = [this](const std::string& rawJson) {
            if (controlStatusSink_) {
                controlStatusSink_->OnControlStatusLine(amsi_ipc::AmsiControlStatusLine{rawJson});
            }
        };
        context.diagLogger = [](const hostguard_demo::HostGuardAmsiAdapterDiag& diag) {
            SentryLog_Info("HostGuardAmsiIpcModule", "%s [%s] %s",
                           diag.level.c_str(),
                           diag.component.c_str(),
                           diag.message.c_str());
        };

        std::string error;
        if (!amsiIpcModule_->Init(adapterConfig, std::move(context), error)) {
            startError_ = "HostGuardAmsiIpcModule Init failed: " + error;
            amsiIpcModule_.reset();
            controlStatusSink_.reset();
            eventSink_.reset();
            ruleProvider_.reset();
            return false;
        }

        started_ = amsiIpcModule_->Start(error);
        if (!started_) {
            startError_ = "HostGuardAmsiIpcModule Start failed: " + error;
            amsiIpcModule_->UnInit();
            amsiIpcModule_.reset();
            controlStatusSink_.reset();
            eventSink_.reset();
            ruleProvider_.reset();
        }
        return started_;
    }

    AmsiIpcHostConfig config = AmsiIpcHostConfig::ForHostGuard();
    config.strictHostGuardMode = options_.strictHostGuardMode;
    config.enableDemoConfigWatcher = options_.enableDemoConfigWatcher;
    config.enableDemoStagingWatcher = options_.enableDemoStagingWatcher;
    config.rulesPipeName = options_.rulesPipeName;
    config.eventsPipeName = options_.eventsPipeName;
    config.controlStatusPipeName = options_.controlStatusPipeName;
    config.configPipeName = options_.configPipeName;

    AmsiIpcHostAdapters adapters;
    adapters.ruleProvider = ruleProvider_.get();
    adapters.eventSink = eventSink_.get();
    adapters.controlStatusSink = controlStatusSink_.get();

    host_.reset(new AmsiIpcHost(config, adapters));
    started_ = host_->Start();
    if (!started_) {
        startError_ = "AmsiIpcHost failed to start";
        host_.reset();
        controlStatusSink_.reset();
        eventSink_.reset();
        ruleProvider_.reset();
    }
    return started_;
}

void HostGuardDemoApp::Stop()
{
    if (amsiIpcModule_) {
        amsiIpcModule_->UnInit();
    }
    if (host_) {
        host_->Stop();
    }
    host_.reset();
    amsiIpcModule_.reset();
    controlStatusSink_.reset();
    eventSink_.reset();
    ruleProvider_.reset();
    started_ = false;
}

bool HostGuardDemoApp::Reload()
{
    if (amsiIpcModule_) {
        std::string error;
        if (!amsiIpcModule_->ReloadRules(1000, error)) {
            startError_ = "HostGuardAmsiIpcModule ReloadRules failed: " + error;
            return false;
        }
        return true;
    }
    if (!host_) {
        return false;
    }
    host_->InvalidateRules();
    lastReload_ = host_->BroadcastReload();
    return true;
}

bool HostGuardDemoApp::PauseDetection()
{
    if (!amsiIpcModule_) {
        startError_ = "AMSI IPC module is not enabled";
        return false;
    }

    std::string error;
    if (!amsiIpcModule_->ApplyPolicy(false, "hostguard-amsi-policy-disabled", 1000, error)) {
        startError_ = "HostGuardAmsiIpcModule PauseDetection failed: " + error;
        return false;
    }
    return true;
}

bool HostGuardDemoApp::ResumeDetection()
{
    if (!amsiIpcModule_) {
        startError_ = "AMSI IPC module is not enabled";
        return false;
    }

    std::string error;
    if (!amsiIpcModule_->ApplyPolicy(true, "hostguard-amsi-policy-enabled", 1000, error)) {
        startError_ = "HostGuardAmsiIpcModule ResumeDetection failed: " + error;
        return false;
    }
    return true;
}

bool HostGuardDemoApp::Unload()
{
    if (amsiIpcModule_) {
        std::string error;
        if (!amsiIpcModule_->Unload(1000, error)) {
            startError_ = "HostGuardAmsiIpcModule Unload failed: " + error;
            return false;
        }
        return true;
    }
    if (!host_) {
        return false;
    }
    lastUnload_ = host_->BroadcastUnload();
    return true;
}

bool HostGuardDemoApp::SetControlState(const std::string& state)
{
    if (!ruleProvider_) {
        startError_ = "rule provider is not initialized";
        return false;
    }

    std::string error;
    if (!ruleProvider_->SetControlState(state, error)) {
        startError_ = error;
        return false;
    }

    if (amsiIpcModule_) {
        if (!amsiIpcModule_->ReloadRules(1000, error)) {
            startError_ = "HostGuardAmsiIpcModule state update failed: " + error;
            return false;
        }
    }
    return true;
}

void HostGuardDemoApp::PrintStatus(std::ostream& output) const
{
    output << "strictHostGuardMode: " << (options_.strictHostGuardMode ? "yes" : "no") << '\n'
           << "pipeMode: " << HostGuardPipeModeName(options_.pipeMode) << '\n'
           << "started: " << (started_ ? "yes" : "no") << '\n'
           << "rulesPath: " << options_.rulesPath << '\n'
           << "logDir: " << options_.logDir << '\n'
           << "rulesPipeName: " << NarrowAscii(options_.rulesPipeName) << '\n'
           << "eventsPipeName: " << NarrowAscii(options_.eventsPipeName) << '\n'
           << "controlStatusPipeName: " << NarrowAscii(options_.controlStatusPipeName) << '\n'
           << "configPipeName: " << NarrowAscii(options_.configPipeName) << '\n'
           << "amsiIpc.enabled: " << (options_.amsiIpc.enabled ? "yes" : "no") << '\n'
           << "amsiIpc.enableRealIpc: " << (options_.amsiIpc.enableRealIpc ? "yes" : "no") << '\n'
           << "amsiIpc.useProductionPipes: " << (options_.amsiIpc.useProductionPipes ? "yes" : "no") << '\n'
           << "enableDemoConfigWatcher: " << (options_.enableDemoConfigWatcher ? "yes" : "no") << '\n'
           << "enableDemoStagingWatcher: " << (options_.enableDemoStagingWatcher ? "yes" : "no") << '\n'
           << "controlState: "
           << (ruleProvider_ ? ruleProvider_->control_state() : std::string("not-ready")) << '\n'
           << "providerCacheReady: "
           << ((ruleProvider_ && ruleProvider_->cache_ready()) ? "yes" : "no") << '\n'
           << "lastReload: reached=" << lastReload_.reached
           << " lastError=" << lastReload_.lastError << '\n'
           << "lastUnload: reached=" << lastUnload_.reached
           << " lastError=" << lastUnload_.lastError << '\n';
    if (amsiIpcModule_) {
        const auto moduleStatus = amsiIpcModule_->GetStatus();
        output << "amsiIpc.moduleStarted: " << (moduleStatus.started ? "yes" : "no") << '\n'
               << "amsiIpc.policyEnabled: " << (moduleStatus.policyEnabled ? "yes" : "no") << '\n'
               << "amsiIpc.policyVersion: " << moduleStatus.policyVersion << '\n'
               << "amsiIpc.lifecycleState: " << moduleStatus.adapter.lifecycleState << '\n'
               << "amsiIpc.ruleRequests: " << moduleStatus.adapter.ruleRequests << '\n'
               << "amsiIpc.eventReceived: " << moduleStatus.adapter.eventReceived << '\n'
               << "amsiIpc.statusReceived: " << moduleStatus.adapter.statusReceived << '\n'
               << "amsiIpc.lastReload: delivered=" << moduleStatus.lastReload.delivered
               << " acked=" << moduleStatus.lastReload.acked
               << " lastError=" << moduleStatus.lastReload.error << '\n'
               << "amsiIpc.lastUnload: delivered=" << moduleStatus.lastUnload.delivered
               << " acked=" << moduleStatus.lastUnload.acked
               << " lastError=" << moduleStatus.lastUnload.error << '\n';
    }
}

bool HostGuardDemoApp::started() const
{
    return started_;
}

const std::string& HostGuardDemoApp::start_error() const
{
    return startError_;
}
