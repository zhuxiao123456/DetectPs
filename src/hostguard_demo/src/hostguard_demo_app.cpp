#include "hostguard_demo_app.h"

#include "amsi_ipc_host.h"
#include "hostguard_file_rule_provider.h"
#include "hostguard_jsonl_control_status_sink.h"
#include "hostguard_jsonl_event_sink.h"
#include "hostguard_paths.h"

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
        options.rulesPipeName = LR"(\\.\pipe\amsi_detect_rules)";
        options.eventsPipeName = LR"(\\.\pipe\amsi_detect_events)";
        options.controlStatusPipeName = LR"(\\.\pipe\amsi_detect_control_status)";
        options.configPipeName = LR"(\\.\pipe\amsi_detect_config)";
        return;
    }

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
    if (host_) {
        host_->Stop();
    }
    host_.reset();
    controlStatusSink_.reset();
    eventSink_.reset();
    ruleProvider_.reset();
    started_ = false;
}

bool HostGuardDemoApp::Reload()
{
    if (!host_) {
        return false;
    }
    host_->InvalidateRules();
    lastReload_ = host_->BroadcastReload();
    return true;
}

bool HostGuardDemoApp::Unload()
{
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
           << "enableDemoConfigWatcher: " << (options_.enableDemoConfigWatcher ? "yes" : "no") << '\n'
           << "enableDemoStagingWatcher: " << (options_.enableDemoStagingWatcher ? "yes" : "no") << '\n'
           << "providerCacheReady: "
           << ((ruleProvider_ && ruleProvider_->cache_ready()) ? "yes" : "no") << '\n'
           << "lastReload: reached=" << lastReload_.reached
           << " lastError=" << lastReload_.lastError << '\n'
           << "lastUnload: reached=" << lastUnload_.reached
           << " lastError=" << lastUnload_.lastError << '\n';
}

bool HostGuardDemoApp::started() const
{
    return started_;
}

const std::string& HostGuardDemoApp::start_error() const
{
    return startError_;
}
