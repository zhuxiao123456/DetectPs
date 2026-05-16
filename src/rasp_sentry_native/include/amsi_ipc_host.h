#pragma once

#include <memory>
#include <string>

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
class NamedPipeServerPool;
} // namespace amsi_ipc

struct AmsiIpcHostConfig {
    std::string logDir;
    std::string rulesPath;
    std::string stagingDir;
};

struct AmsiIpcHostAdapters {
    amsi_ipc::IAmsiEventSink* eventSink = nullptr;
    amsi_ipc::IAmsiControlStatusSink* controlStatusSink = nullptr;
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
