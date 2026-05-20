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

#include <iomanip>
#include <iostream>
#include <sstream>

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

    if (options_.pipeMode == HostGuardPipeMode::Production) {
        if (PipeServerExists(options_.rulesPipeName)) {
            startError_ = "production rules pipe is already served: " + NarrowAscii(options_.rulesPipeName);
            return false;
        }
        if (PipeServerExists(options_.eventsPipeName)) {
            startError_ = "production events pipe is already served: " + NarrowAscii(options_.eventsPipeName);
            return false;
        }
        if (PipeServerExists(options_.controlStatusPipeName)) {
            startError_ = "production control status pipe is already served: " +
                          NarrowAscii(options_.controlStatusPipeName);
            return false;
        }
        if (PipeServerExists(options_.configPipeName)) {
            startError_ = "production config pipe is already served: " + NarrowAscii(options_.configPipeName);
            return false;
        }
    }

    hostguard_demo::EnsureDirectory(options_.logDir);

    ruleProvider_.reset(new HostGuardFileRuleProvider(options_.rulesPath));
    eventSink_.reset(new HostGuardJsonlEventSink(options_.logDir));
    controlStatusSink_.reset(new HostGuardJsonlControlStatusSink(options_.logDir));

    if (options_.amsiIpc.enabled) {
        amsiIpcAdapter_.reset(new hostguard_demo::HostGuardAmsiIpcAdapter());

        hostguard_demo::HostGuardAmsiIpcConfig adapterConfig;
        adapterConfig.enableRealIpc = options_.amsiIpc.enableRealIpc;
        adapterConfig.useProductionPipes = options_.amsiIpc.useProductionPipes;
        adapterConfig.rulesPipeName = options_.rulesPipeName;
        adapterConfig.eventsPipeName = options_.eventsPipeName;
        adapterConfig.controlStatusPipeName = options_.controlStatusPipeName;
        adapterConfig.configPipeName = options_.configPipeName;

        std::string error;
        if (!amsiIpcAdapter_->Init(adapterConfig, error)) {
            startError_ = "HostGuardAmsiIpcAdapter Init failed: " + error;
            amsiIpcAdapter_.reset();
            controlStatusSink_.reset();
            eventSink_.reset();
            ruleProvider_.reset();
            return false;
        }

        amsiIpcAdapter_->SetDetectionEventCallback([this](const hostguard_demo::HostGuardAmsiEventEnvelope& event) {
            if (eventSink_) {
                eventSink_->OnEventLine(amsi_ipc::AmsiEventLine{event.rawJson});
            }
        });
        amsiIpcAdapter_->SetDllDiagnosticLogCallback([this](const hostguard_demo::HostGuardAmsiEventEnvelope& log) {
            if (eventSink_) {
                eventSink_->OnEventLine(amsi_ipc::AmsiEventLine{log.rawJson});
            }
        });
        amsiIpcAdapter_->SetStatusCallback([this](const std::string& rawJson) {
            if (controlStatusSink_) {
                controlStatusSink_->OnControlStatusLine(amsi_ipc::AmsiControlStatusLine{rawJson});
            }
        });
        amsiIpcAdapter_->SetAdapterDiagCallback([](const hostguard_demo::HostGuardAmsiAdapterDiag& diag) {
            SentryLog_Info("HostGuardAmsiIpcAdapter", "%s [%s] %s",
                           diag.level.c_str(),
                           diag.component.c_str(),
                           diag.message.c_str());
        });

        amsi_ipc::AmsiRuleResponse allRules;
        amsi_ipc::AmsiRuleResponse amsiRules;
        if (!ruleProvider_->BuildRulesResponse("GET_ALL_RULES", allRules, error) ||
            !ruleProvider_->BuildRulesResponse("GET_RULES", amsiRules, error)) {
            startError_ = "HostGuardAmsiIpcAdapter failed to read rules: " + error;
            amsiIpcAdapter_.reset();
            controlStatusSink_.reset();
            eventSink_.reset();
            ruleProvider_.reset();
            return false;
        }

        const std::string ruleHash = StableHash(allRules.json + "\n" + amsiRules.json);
        if (!amsiIpcAdapter_->UpdateRules(allRules.json,
                                          amsiRules.json,
                                          "hostguard-demo-" + ruleHash,
                                          ruleHash,
                                          error)) {
            startError_ = "HostGuardAmsiIpcAdapter UpdateRules failed: " + error;
            amsiIpcAdapter_.reset();
            controlStatusSink_.reset();
            eventSink_.reset();
            ruleProvider_.reset();
            return false;
        }
        if (!amsiIpcAdapter_->SetDetectionEnabled(true, "hostguard-demo-policy-enabled", error)) {
            startError_ = "HostGuardAmsiIpcAdapter SetDetectionEnabled failed: " + error;
            amsiIpcAdapter_.reset();
            controlStatusSink_.reset();
            eventSink_.reset();
            ruleProvider_.reset();
            return false;
        }

        started_ = amsiIpcAdapter_->Start(error);
        if (!started_) {
            startError_ = "HostGuardAmsiIpcAdapter Start failed: " + error;
            amsiIpcAdapter_->Stop();
            amsiIpcAdapter_.reset();
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
    if (amsiIpcAdapter_) {
        amsiIpcAdapter_->Stop();
    }
    if (host_) {
        host_->Stop();
    }
    host_.reset();
    amsiIpcAdapter_.reset();
    controlStatusSink_.reset();
    eventSink_.reset();
    ruleProvider_.reset();
    started_ = false;
}

bool HostGuardDemoApp::Reload()
{
    if (amsiIpcAdapter_) {
        std::string error;
        amsi_ipc::AmsiRuleResponse allRules;
        amsi_ipc::AmsiRuleResponse amsiRules;
        if (ruleProvider_) {
            ruleProvider_->InvalidateRuleCache();
        }
        if (ruleProvider_ &&
            ruleProvider_->BuildRulesResponse("GET_ALL_RULES", allRules, error) &&
            ruleProvider_->BuildRulesResponse("GET_RULES", amsiRules, error)) {
            const std::string ruleHash = StableHash(allRules.json + "\n" + amsiRules.json);
            if (!amsiIpcAdapter_->UpdateRules(allRules.json,
                                              amsiRules.json,
                                              "hostguard-demo-" + ruleHash,
                                              ruleHash,
                                              error)) {
                startError_ = "HostGuardAmsiIpcAdapter Reload UpdateRules failed: " + error;
                return false;
            }
        } else {
            startError_ = "HostGuardAmsiIpcAdapter Reload failed to read rules: " + error;
            return false;
        }
        lastAdapterReload_ = hostguard_demo::HostGuardAmsiBroadcastResult{};
        return amsiIpcAdapter_->Reload(1000, lastAdapterReload_);
    }
    if (!host_) {
        return false;
    }
    host_->InvalidateRules();
    lastReload_ = host_->BroadcastReload();
    return true;
}

bool HostGuardDemoApp::Unload()
{
    if (amsiIpcAdapter_) {
        lastAdapterUnload_ = hostguard_demo::HostGuardAmsiBroadcastResult{};
        return amsiIpcAdapter_->Unload(1000, lastAdapterUnload_);
    }
    if (!host_) {
        return false;
    }
    lastUnload_ = host_->BroadcastUnload();
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
           << "providerCacheReady: "
           << ((ruleProvider_ && ruleProvider_->cache_ready()) ? "yes" : "no") << '\n'
           << "lastReload: reached=" << lastReload_.reached
           << " lastError=" << lastReload_.lastError << '\n'
           << "lastUnload: reached=" << lastUnload_.reached
           << " lastError=" << lastUnload_.lastError << '\n';
    if (amsiIpcAdapter_) {
        const auto adapterStatus = amsiIpcAdapter_->GetStatus();
        output << "amsiIpc.lifecycleState: " << adapterStatus.lifecycleState << '\n'
               << "amsiIpc.ruleRequests: " << adapterStatus.ruleRequests << '\n'
               << "amsiIpc.eventReceived: " << adapterStatus.eventReceived << '\n'
               << "amsiIpc.statusReceived: " << adapterStatus.statusReceived << '\n'
               << "amsiIpc.lastReload: delivered=" << lastAdapterReload_.delivered
               << " acked=" << lastAdapterReload_.acked
               << " lastError=" << lastAdapterReload_.error << '\n'
               << "amsiIpc.lastUnload: delivered=" << lastAdapterUnload_.delivered
               << " acked=" << lastAdapterUnload_.acked
               << " lastError=" << lastAdapterUnload_.error << '\n';
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
