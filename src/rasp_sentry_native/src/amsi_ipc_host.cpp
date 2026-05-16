#include "amsi_ipc_host.h"

#include "amsi_staging_watcher.h"
#include "config_watcher.h"
#include "control_status_collector.h"
#include "event_collector.h"
#include "rule_server.h"
#include "sentry_log.h"

#include <utility>

AmsiIpcHost::AmsiIpcHost(AmsiIpcHostConfig config)
    : config_(std::move(config))
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

    eventCollector_.reset(new EventCollector(config_.logDir));
    controlStatusCollector_.reset(new ControlStatusCollector(config_.logDir));
    ruleServer_.reset(new RuleServer(config_.rulesPath));
    configWatcher_.reset(new ConfigWatcher(config_.rulesPath, ruleServer_.get()));
    stagingWatcher_.reset(new AmsiStagingWatcher(config_.stagingDir, eventCollector_->GetDrainQueue()));

    // Keep the demo startup order stable with the previous rasp_sentry main().
    eventCollector_->Start();
    stage_ = StartStage::EventCollector;
    SentryLog_Info("Program", "EventCollector started - %d threads on amsi_detect_events",
                   EventCollector::kThreadCount);

    controlStatusCollector_->Start();
    stage_ = StartStage::ControlStatusCollector;
    SentryLog_Info("Program", "ControlStatusCollector started - %d threads on amsi_detect_control_status",
                   ControlStatusCollector::kThreadCount);

    ruleServer_->Start();
    stage_ = StartStage::RuleServer;
    SentryLog_Info("Program", "RuleServer started - %d threads on amsi_detect_rules",
                   RuleServer::kThreadCount);

    configWatcher_->Start();
    stage_ = StartStage::ConfigWatcher;
    SentryLog_Info("Program", "ConfigWatcher started - watching %s", config_.rulesPath.c_str());

    stagingWatcher_->Start();
    stage_ = StartStage::AmsiStagingWatcher;
    SentryLog_Info("Program", "AmsiStagingWatcher started - staging: %s", config_.stagingDir.c_str());

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
    if (stage >= static_cast<int>(StartStage::EventCollector) && eventCollector_) {
        eventCollector_->Stop();
    }

    stagingWatcher_.reset();
    configWatcher_.reset();
    ruleServer_.reset();
    controlStatusCollector_.reset();
    eventCollector_.reset();

    stage_ = StartStage::None;
    started_ = false;
}
