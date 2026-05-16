#pragma once

#include <memory>
#include <string>

class AmsiStagingWatcher;
class ConfigWatcher;
class ControlStatusCollector;
class EventCollector;
class RuleServer;

struct AmsiIpcHostConfig {
    std::string logDir;
    std::string rulesPath;
    std::string stagingDir;
};

class AmsiIpcHost {
public:
    explicit AmsiIpcHost(AmsiIpcHostConfig config);
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
    bool started_ = false;
    StartStage stage_ = StartStage::None;

    std::unique_ptr<EventCollector> eventCollector_;
    std::unique_ptr<ControlStatusCollector> controlStatusCollector_;
    std::unique_ptr<RuleServer> ruleServer_;
    std::unique_ptr<ConfigWatcher> configWatcher_;
    std::unique_ptr<AmsiStagingWatcher> stagingWatcher_;
};
