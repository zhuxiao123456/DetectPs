#pragma once

#include <memory>
#include <cstdint>
#include <string>

#include "amsi_config_broadcaster.h"

class AmsiStagingWatcher;
class ConfigWatcher;
class ControlStatusCollector;
class EventCollector;
class RuleServer;

namespace amsi_ipc {
class AmsiControlStatusChannel;
class AmsiEventChannel;
class IAmsiControlStatusSink;
class IAmsiEventSink;
class IAmsiRuleProvider;
class NamedPipeServerPool;
} // namespace amsi_ipc

struct AmsiIpcHostConfig {
    std::string logDir;
    std::string rulesPath;
    std::string stagingDir;
    bool enableDemoConfigWatcher = true;
    bool enableDemoStagingWatcher = true;
    std::wstring rulesPipeName;
    std::wstring eventsPipeName;
    std::wstring controlStatusPipeName;
    std::wstring configPipeName;
};

struct AmsiIpcHostAdapters {
    amsi_ipc::IAmsiEventSink* eventSink = nullptr;
    amsi_ipc::IAmsiControlStatusSink* controlStatusSink = nullptr;
    amsi_ipc::IAmsiRuleProvider* ruleProvider = nullptr;
};

class AmsiIpcHost {
public:
    explicit AmsiIpcHost(AmsiIpcHostConfig config);
    AmsiIpcHost(AmsiIpcHostConfig config, AmsiIpcHostAdapters adapters);
    ~AmsiIpcHost();

    AmsiIpcHost(const AmsiIpcHost&) = delete;
    AmsiIpcHost& operator=(const AmsiIpcHost&) = delete;

    bool Start();
    void Stop();
    void InvalidateRules();
    amsi_ipc::AmsiBroadcastResult BroadcastReload(int maxListeners = 32,
                                                  std::uint32_t timeoutMs = 500);
    amsi_ipc::AmsiBroadcastResult BroadcastUnload(int maxListeners = 32,
                                                  std::uint32_t timeoutMs = 500);

private:
    enum class StartStage {
        None,
        EventCollector,
        ControlStatusCollector,
        RuleServer,
        ConfigWatcher,
        AmsiStagingWatcher,
    };

    AmsiIpcHostConfig config_;
    AmsiIpcHostAdapters adapters_;
    bool started_ = false;
    StartStage stage_ = StartStage::None;

    std::unique_ptr<EventCollector> eventCollector_;
    std::unique_ptr<ControlStatusCollector> controlStatusCollector_;
    std::unique_ptr<amsi_ipc::AmsiEventChannel> injectedEventChannel_;
    std::unique_ptr<amsi_ipc::NamedPipeServerPool> injectedEventPipePool_;
    std::unique_ptr<amsi_ipc::AmsiControlStatusChannel> injectedControlStatusChannel_;
    std::unique_ptr<amsi_ipc::NamedPipeServerPool> injectedControlStatusPipePool_;
    std::unique_ptr<RuleServer> ruleServer_;
    std::unique_ptr<ConfigWatcher> configWatcher_;
    std::unique_ptr<AmsiStagingWatcher> stagingWatcher_;
};
