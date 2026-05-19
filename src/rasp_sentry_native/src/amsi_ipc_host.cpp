#include "amsi_ipc_host.h"

#include "amsi_config_broadcaster.h"
#include "amsi_control_status_channel.h"
#include "amsi_event_channel.h"
#include "amsi_pipe_names.h"
#include "amsi_rule_provider.h"
#include "amsi_staging_watcher.h"
#include "config_watcher.h"
#include "control_status_collector.h"
#include "event_collector.h"
#include "named_pipe_server_pool.h"
#include "rule_server.h"
#include "sentry_log.h"

#include <utility>

namespace {

std::wstring OrDefaultPipeName(const std::wstring& configured,
                               const wchar_t* defaultName)
{
    return configured.empty() ? std::wstring(defaultName) : configured;
}

} // namespace

AmsiIpcHostConfig AmsiIpcHostConfig::ForDemo(std::string logDir,
                                             std::string rulesPath,
                                             std::string stagingDir)
{
    AmsiIpcHostConfig config;
    config.logDir = std::move(logDir);
    config.rulesPath = std::move(rulesPath);
    config.stagingDir = std::move(stagingDir);
    config.enableDemoConfigWatcher = true;
    config.enableDemoStagingWatcher = true;
    config.strictHostGuardMode = false;
    return config;
}

AmsiIpcHostConfig AmsiIpcHostConfig::ForHostGuard()
{
    AmsiIpcHostConfig config;
    config.enableDemoConfigWatcher = false;
    config.enableDemoStagingWatcher = false;
    config.strictHostGuardMode = true;
    return config;
}

AmsiIpcHost::AmsiIpcHost(AmsiIpcHostConfig config)
    : config_(std::move(config))
{
}

AmsiIpcHost::AmsiIpcHost(AmsiIpcHostConfig config, AmsiIpcHostAdapters adapters)
    : config_(std::move(config)),
      adapters_(adapters)
{
}

AmsiIpcHost::~AmsiIpcHost()
{
    Stop();
}

bool AmsiIpcHost::Start()
{
    if (started_) {
        return true;
    }

    if (config_.strictHostGuardMode &&
        (!adapters_.ruleProvider || !adapters_.eventSink || !adapters_.controlStatusSink)) {
        SentryLog_Error("Program",
                        "AmsiIpcHost strict HostGuard mode requires ruleProvider, eventSink, and controlStatusSink");
        return false;
    }

    const std::wstring rulesPipeName = OrDefaultPipeName(config_.rulesPipeName,
                                                         amsi_ipc::kRulesPipeName);
    if (adapters_.ruleProvider) {
        ruleServer_.reset(new RuleServer(*adapters_.ruleProvider, rulesPipeName));
    } else {
        ruleServer_.reset(new RuleServer(config_.rulesPath, rulesPipeName));
    }
    if (config_.enableDemoConfigWatcher) {
        configWatcher_.reset(new ConfigWatcher(config_.rulesPath, ruleServer_->RuleProvider()));
    }
    if (!adapters_.eventSink) {
        eventCollector_.reset(new EventCollector(config_.logDir));
        if (config_.enableDemoStagingWatcher) {
            stagingWatcher_.reset(new AmsiStagingWatcher(config_.stagingDir, eventCollector_->GetDrainQueue()));
        }
    }
    if (!adapters_.controlStatusSink) {
        controlStatusCollector_.reset(new ControlStatusCollector(config_.logDir));
    }

    // Keep the demo startup order stable with the previous rasp_sentry main().
    if (adapters_.eventSink) {
        injectedEventChannel_.reset(new amsi_ipc::AmsiEventChannel(*adapters_.eventSink));
        const std::wstring eventsPipeName = OrDefaultPipeName(config_.eventsPipeName,
                                                              amsi_ipc::kEventsPipeName);
        injectedEventPipePool_.reset(new amsi_ipc::NamedPipeServerPool(
            eventsPipeName,
            EventCollector::kThreadCount,
            *injectedEventChannel_,
            0,
            65536,
            PIPE_ACCESS_INBOUND,
            GENERIC_WRITE));
        if (!injectedEventPipePool_->Start()) {
            SentryLog_Error("Program", "Failed to start one or more injected event pipe worker thread(s)");
        }
    } else {
        eventCollector_->Start();
    }
    stage_ = StartStage::EventCollector;
    SentryLog_Info("Program", "EventCollector started - %d threads on amsi_detect_events",
                   EventCollector::kThreadCount);

    if (adapters_.controlStatusSink) {
        injectedControlStatusChannel_.reset(new amsi_ipc::AmsiControlStatusChannel(*adapters_.controlStatusSink));
        const std::wstring controlStatusPipeName = OrDefaultPipeName(config_.controlStatusPipeName,
                                                                     amsi_ipc::kControlStatusPipeName);
        injectedControlStatusPipePool_.reset(new amsi_ipc::NamedPipeServerPool(
            controlStatusPipeName,
            ControlStatusCollector::kThreadCount,
            *injectedControlStatusChannel_,
            0,
            65536,
            PIPE_ACCESS_INBOUND,
            GENERIC_WRITE));
        if (!injectedControlStatusPipePool_->Start()) {
            SentryLog_Error("Program", "Failed to start one or more injected control status pipe worker thread(s)");
        }
    } else {
        controlStatusCollector_->Start();
    }
    stage_ = StartStage::ControlStatusCollector;
    SentryLog_Info("Program", "ControlStatusCollector started - %d threads on amsi_detect_control_status",
                   ControlStatusCollector::kThreadCount);

    ruleServer_->Start();
    stage_ = StartStage::RuleServer;
    SentryLog_Info("Program", "RuleServer started - %d threads on amsi_detect_rules",
                   RuleServer::kThreadCount);

    if (configWatcher_) {
        configWatcher_->Start();
        stage_ = StartStage::ConfigWatcher;
        SentryLog_Info("Program", "ConfigWatcher started - watching %s", config_.rulesPath.c_str());
    }

    if (stagingWatcher_) {
        stagingWatcher_->Start();
        stage_ = StartStage::AmsiStagingWatcher;
        SentryLog_Info("Program", "AmsiStagingWatcher started - staging: %s", config_.stagingDir.c_str());
    }

    started_ = true;
    return true;
}

void AmsiIpcHost::Stop()
{
    const int stage = static_cast<int>(stage_);
    if (stage >= static_cast<int>(StartStage::AmsiStagingWatcher) && stagingWatcher_) {
        stagingWatcher_->Stop();
    }
    if (stage >= static_cast<int>(StartStage::ConfigWatcher) && configWatcher_) {
        configWatcher_->Stop();
    }
    if (stage >= static_cast<int>(StartStage::RuleServer) && ruleServer_) {
        ruleServer_->Stop();
    }
    if (stage >= static_cast<int>(StartStage::ControlStatusCollector) && controlStatusCollector_) {
        controlStatusCollector_->Stop();
    }
    if (stage >= static_cast<int>(StartStage::ControlStatusCollector) && injectedControlStatusPipePool_) {
        injectedControlStatusPipePool_->Stop();
    }
    if (stage >= static_cast<int>(StartStage::EventCollector) && eventCollector_) {
        eventCollector_->Stop();
    }
    if (stage >= static_cast<int>(StartStage::EventCollector) && injectedEventPipePool_) {
        injectedEventPipePool_->Stop();
    }

    stagingWatcher_.reset();
    configWatcher_.reset();
    ruleServer_.reset();
    injectedControlStatusPipePool_.reset();
    injectedControlStatusChannel_.reset();
    controlStatusCollector_.reset();
    injectedEventPipePool_.reset();
    injectedEventChannel_.reset();
    eventCollector_.reset();

    stage_ = StartStage::None;
    started_ = false;
}

void AmsiIpcHost::InvalidateRules()
{
    if (adapters_.ruleProvider) {
        adapters_.ruleProvider->InvalidateRuleCache();
        return;
    }
    if (ruleServer_) {
        ruleServer_->InvalidateRuleCache();
    }
}

amsi_ipc::AmsiBroadcastResult AmsiIpcHost::BroadcastReload(int maxListeners,
                                                           std::uint32_t timeoutMs)
{
    const std::wstring configPipeName = OrDefaultPipeName(config_.configPipeName,
                                                          amsi_ipc::kConfigPipeName);
    const amsi_ipc::AmsiConfigBroadcaster broadcaster(configPipeName);
    return broadcaster.Broadcast(amsi_ipc::AmsiControlSignal::Reload,
                                 maxListeners,
                                 timeoutMs);
}

amsi_ipc::AmsiBroadcastResult AmsiIpcHost::BroadcastUnload(int maxListeners,
                                                           std::uint32_t timeoutMs)
{
    const std::wstring configPipeName = OrDefaultPipeName(config_.configPipeName,
                                                          amsi_ipc::kConfigPipeName);
    const amsi_ipc::AmsiConfigBroadcaster broadcaster(configPipeName);
    return broadcaster.Broadcast(amsi_ipc::AmsiControlSignal::Unload,
                                 maxListeners,
                                 timeoutMs);
}

amsi_ipc::AmsiBroadcastResult AmsiIpcHost::BroadcastPauseDetection(int maxListeners,
                                                                   std::uint32_t timeoutMs)
{
    const std::wstring configPipeName = OrDefaultPipeName(config_.configPipeName,
                                                          amsi_ipc::kConfigPipeName);
    const amsi_ipc::AmsiConfigBroadcaster broadcaster(configPipeName);
    return broadcaster.Broadcast(amsi_ipc::AmsiControlSignal::PauseDetection,
                                 maxListeners,
                                 timeoutMs);
}

amsi_ipc::AmsiBroadcastResult AmsiIpcHost::BroadcastResumeDetection(int maxListeners,
                                                                    std::uint32_t timeoutMs)
{
    const std::wstring configPipeName = OrDefaultPipeName(config_.configPipeName,
                                                          amsi_ipc::kConfigPipeName);
    const amsi_ipc::AmsiConfigBroadcaster broadcaster(configPipeName);
    return broadcaster.Broadcast(amsi_ipc::AmsiControlSignal::ResumeDetection,
                                 maxListeners,
                                 timeoutMs);
}
