#pragma once

#include "amsi_config_broadcaster.h"

#include <iosfwd>
#include <memory>
#include <string>

class AmsiIpcHost;
class HostGuardFileRuleProvider;
class HostGuardJsonlControlStatusSink;
class HostGuardJsonlEventSink;

enum class HostGuardPipeMode {
    Demo,
    Production,
};

struct HostGuardDemoOptions {
    std::string rulesPath = "config\\rasp_rules.json";
    std::string logDir = "logs";
    HostGuardPipeMode pipeMode = HostGuardPipeMode::Demo;
    bool strictHostGuardMode = true;
    bool enableDemoConfigWatcher = false;
    bool enableDemoStagingWatcher = false;
    std::wstring rulesPipeName = LR"(\\.\pipe\amsi_detect_rules_demo)";
    std::wstring eventsPipeName = LR"(\\.\pipe\amsi_detect_events_demo)";
    std::wstring controlStatusPipeName = LR"(\\.\pipe\amsi_detect_control_status_demo)";
    std::wstring configPipeName = LR"(\\.\pipe\amsi_detect_config_demo)";
};

const char* HostGuardPipeModeName(HostGuardPipeMode mode);
void ApplyHostGuardPipeMode(HostGuardDemoOptions& options, HostGuardPipeMode mode);

class HostGuardDemoApp {
public:
    explicit HostGuardDemoApp(HostGuardDemoOptions options);
    ~HostGuardDemoApp();

    HostGuardDemoApp(const HostGuardDemoApp&) = delete;
    HostGuardDemoApp& operator=(const HostGuardDemoApp&) = delete;

    bool Start();
    void Stop();
    bool Reload();
    bool Unload();
    void PrintStatus(std::ostream& output) const;

    bool started() const;
    const std::string& start_error() const;

private:
    HostGuardDemoOptions options_;
    bool started_ = false;
    std::string startError_;
    amsi_ipc::AmsiBroadcastResult lastReload_;
    amsi_ipc::AmsiBroadcastResult lastUnload_;

    std::unique_ptr<HostGuardFileRuleProvider> ruleProvider_;
    std::unique_ptr<HostGuardJsonlEventSink> eventSink_;
    std::unique_ptr<HostGuardJsonlControlStatusSink> controlStatusSink_;
    std::unique_ptr<AmsiIpcHost> host_;
};
