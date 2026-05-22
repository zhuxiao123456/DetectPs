//
// Created by Codex on 2026/5/21.
//

#include "AmsiIpcRuntime.h"

#include "../amsi_ipc_host/include/AmsiConfigBroadcaster.h"
#include "../amsi_ipc_host/include/AmsiControlStatusChannel.h"
#include "../amsi_ipc_host/include/AmsiControlStatusSink.h"
#include "../amsi_ipc_host/include/AmsiEventChannel.h"
#include "../amsi_ipc_host/include/AmsiEventSink.h"
#include "../amsi_ipc_host/include/AmsiRuleChannel.h"
#include "../amsi_ipc_host/include/AmsiRuleProvider.h"
#include "../amsi_ipc_host/include/NamedPipeServerPool.h"

#include "AmsiDetectGlobalParam.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <mutex>
#include <utility>

namespace Engine {
    namespace {

        const wchar_t *kRulesPipeName = L"\\\\.\\pipe\\amsi_detect_rules";
        const wchar_t *kEventsPipeName = L"\\\\.\\pipe\\amsi_detect_events";
        const wchar_t *kControlStatusPipeName = L"\\\\.\\pipe\\amsi_detect_control_status";
        const wchar_t *kConfigPipeName = L"\\\\.\\pipe\\amsi_detect_config";

        const int kRulePipeThreads = 8;
        const int kEventPipeThreads = 4;
        const int kStatusPipeThreads = 2;
        const int kBroadcastMaxListeners = 32;

        class RuntimeRuleProvider final : public amsi_ipc::IAmsiRuleProvider {
        public:
            bool UpdateSnapshot(const AmsiRuleSnapshot &snapshot, std::string &error)
            {
                if (snapshot.allRulesJson.empty()) {
                    error = "all rules json is empty";
                    return false;
                }
                if (snapshot.amsiRulesJson.empty()) {
                    error = "amsi rules json is empty";
                    return false;
                }
                if (snapshot.version.empty()) {
                    error = "rule version is empty";
                    return false;
                }

                std::lock_guard<std::mutex> lock(mutex_);
                snapshot_ = snapshot;
                error.clear();
                return true;
            }

            bool BuildRulesResponse(const std::string &command,
                                    amsi_ipc::AmsiRuleResponse &out,
                                    std::string &error) override
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (command == "GET_RULES") {
                    out.json = snapshot_.amsiRulesJson;
                    error.clear();
                    return !out.json.empty();
                }
                if (command == "GET_ALL_RULES") {
                    out.json = snapshot_.allRulesJson;
                    error.clear();
                    return !out.json.empty();
                }

                error = "unsupported rules command: " + command;
                return false;
            }

            void InvalidateRuleCache() override {}

        private:
            std::mutex mutex_;
            AmsiRuleSnapshot snapshot_;
        };

        class RuntimeEventSink final : public amsi_ipc::IAmsiEventSink {
        public:
            void OnEventLine(const amsi_ipc::AmsiEventLine &event) override
            {
                InfoLogf1(AmsiDetect::GetLoggerPtr(), "Recv amsi event payload: %s.", event.payload);
            }
        };

        class RuntimeControlStatusSink final : public amsi_ipc::IAmsiControlStatusSink {
        public:
            void OnControlStatusLine(const amsi_ipc::AmsiControlStatusLine &status) override
            {
                InfoLogf1(AmsiDetect::GetLoggerPtr(), "Recv amsi control status payload: %s.", status.payload);
            }
        };

        bool BroadcastSucceeded(const amsi_ipc::AmsiBroadcastResult &result, std::string &error)
        {
            if (result.lastError != 0) {
                error = "broadcast failed, lastError=" + std::to_string(result.lastError);
                return false;
            }

            error.clear();
            return true;
        }

        bool PipeHasExistingServer(const wchar_t *pipeName)
        {
            if (WaitNamedPipeW(pipeName, 1)) {
                return true;
            }

            const DWORD lastError = GetLastError();
            return lastError != ERROR_FILE_NOT_FOUND && lastError != ERROR_PATH_NOT_FOUND;
        }

    }

    struct AmsiIpcRuntime::Impl {
        AmsiIpcRuntimeConfig config;
        AmsiRuleSnapshot snapshot;

        std::unique_ptr<RuntimeRuleProvider> ruleProvider;
        std::unique_ptr<RuntimeEventSink> eventSink;
        std::unique_ptr<RuntimeControlStatusSink> statusSink;

        std::unique_ptr<amsi_ipc::AmsiRuleChannel> ruleChannel;
        std::unique_ptr<amsi_ipc::AmsiEventChannel> eventChannel;
        std::unique_ptr<amsi_ipc::AmsiControlStatusChannel> statusChannel;

        std::unique_ptr<amsi_ipc::NamedPipeServerPool> rulePool;
        std::unique_ptr<amsi_ipc::NamedPipeServerPool> eventPool;
        std::unique_ptr<amsi_ipc::NamedPipeServerPool> statusPool;

        std::unique_ptr<amsi_ipc::AmsiConfigBroadcaster> broadcaster;

        bool initialized = false;
        bool running = false;

        void ResetRuntimeObjects()
        {
            broadcaster.reset();

            statusPool.reset();
            eventPool.reset();
            rulePool.reset();

            statusChannel.reset();
            eventChannel.reset();
            ruleChannel.reset();

            statusSink.reset();
            eventSink.reset();
            ruleProvider.reset();
        }

        void StopPools()
        {
            if (statusPool) {
                statusPool->Stop();
            }
            if (eventPool) {
                eventPool->Stop();
            }
            if (rulePool) {
                rulePool->Stop();
            }
        }
    };

    AmsiIpcRuntime::AmsiIpcRuntime() : m_impl(new Impl())
    {
    }

    AmsiIpcRuntime::~AmsiIpcRuntime()
    {
        std::string error;
        Stop(3000, error);
    }

    bool AmsiIpcRuntime::Init(const AmsiIpcRuntimeConfig &config, std::string &error)
    {
        if (!config.amsiIpcEnabled) {
            error = "amsi ipc is disabled";
            return false;
        }
        if (!config.enableRealIpc) {
            error = "real ipc is disabled";
            return false;
        }
        if (!config.useProductionPipes) {
            error = "production pipe mode is required";
            return false;
        }

        m_impl->config = config;
        m_impl->initialized = true;
        m_impl->running = false;
        error.clear();
        InfoLog(AmsiDetect::GetLoggerPtr(), "Amsi ipc runtime initialized with production pipes.");
        return true;
    }

    bool AmsiIpcRuntime::Start(const AmsiRuleSnapshot &snapshot, std::string &error)
    {
        if (!m_impl->initialized) {
            error = "amsi ipc runtime is not initialized";
            return false;
        }
        if (m_impl->running) {
            return UpdateRules(snapshot, error);
        }

        m_impl->ruleProvider.reset(new RuntimeRuleProvider());
        if (!m_impl->ruleProvider->UpdateSnapshot(snapshot, error)) {
            m_impl->ResetRuntimeObjects();
            return false;
        }

        if (PipeHasExistingServer(kRulesPipeName)) {
            error = "production rules pipe already has a server";
            m_impl->ResetRuntimeObjects();
            return false;
        }
        if (PipeHasExistingServer(kEventsPipeName)) {
            error = "production events pipe already has a server";
            m_impl->ResetRuntimeObjects();
            return false;
        }
        if (PipeHasExistingServer(kControlStatusPipeName)) {
            error = "production control status pipe already has a server";
            m_impl->ResetRuntimeObjects();
            return false;
        }

        m_impl->eventSink.reset(new RuntimeEventSink());
        m_impl->statusSink.reset(new RuntimeControlStatusSink());

        m_impl->ruleChannel.reset(new amsi_ipc::AmsiRuleChannel(*m_impl->ruleProvider));
        m_impl->eventChannel.reset(new amsi_ipc::AmsiEventChannel(*m_impl->eventSink));
        m_impl->statusChannel.reset(new amsi_ipc::AmsiControlStatusChannel(*m_impl->statusSink));

        m_impl->rulePool.reset(new amsi_ipc::NamedPipeServerPool(kRulesPipeName, kRulePipeThreads, *m_impl->ruleChannel));
        m_impl->eventPool.reset(new amsi_ipc::NamedPipeServerPool(kEventsPipeName, kEventPipeThreads, *m_impl->eventChannel));
        m_impl->statusPool.reset(new amsi_ipc::NamedPipeServerPool(kControlStatusPipeName, kStatusPipeThreads, *m_impl->statusChannel));

        if (!m_impl->rulePool->Start()) {
            error = "start rules pipe failed";
            m_impl->StopPools();
            m_impl->ResetRuntimeObjects();
            return false;
        }
        if (!m_impl->eventPool->Start()) {
            error = "start events pipe failed";
            m_impl->StopPools();
            m_impl->ResetRuntimeObjects();
            return false;
        }
        if (!m_impl->statusPool->Start()) {
            error = "start control status pipe failed";
            m_impl->StopPools();
            m_impl->ResetRuntimeObjects();
            return false;
        }

        m_impl->broadcaster.reset(new amsi_ipc::AmsiConfigBroadcaster(kConfigPipeName));
        m_impl->snapshot = snapshot;
        m_impl->running = true;

        InfoLogf2(AmsiDetect::GetLoggerPtr(), "Amsi ipc runtime started, rule version=%s hash=%s.",
                  snapshot.version, snapshot.hash);
        error.clear();
        return true;
    }

    bool AmsiIpcRuntime::Stop(uint32_t, std::string &error)
    {
        if (!m_impl) {
            error.clear();
            return true;
        }

        m_impl->StopPools();
        m_impl->ResetRuntimeObjects();
        m_impl->running = false;
        error.clear();
        InfoLog(AmsiDetect::GetLoggerPtr(), "Amsi ipc runtime stopped.");
        return true;
    }

    bool AmsiIpcRuntime::PauseDetection(uint32_t timeoutMs, std::string &error)
    {
        if (!m_impl->running || !m_impl->broadcaster) {
            error.clear();
            return true;
        }

        const amsi_ipc::AmsiBroadcastResult result =
            m_impl->broadcaster->Broadcast(amsi_ipc::AmsiControlSignal::PauseDetection,
                                           kBroadcastMaxListeners,
                                           timeoutMs);
        return BroadcastSucceeded(result, error);
    }

    bool AmsiIpcRuntime::UpdateRules(const AmsiRuleSnapshot &snapshot, std::string &error)
    {
        if (!m_impl->initialized) {
            error = "amsi ipc runtime is not initialized";
            return false;
        }

        if (m_impl->ruleProvider && !m_impl->ruleProvider->UpdateSnapshot(snapshot, error)) {
            return false;
        }

        m_impl->snapshot = snapshot;
        error.clear();
        return true;
    }

    bool AmsiIpcRuntime::Reload(uint32_t timeoutMs, std::string &error)
    {
        if (!m_impl->running || !m_impl->broadcaster) {
            error = "amsi ipc runtime is not running";
            return false;
        }

        const amsi_ipc::AmsiBroadcastResult result =
            m_impl->broadcaster->Broadcast(amsi_ipc::AmsiControlSignal::Reload,
                                           kBroadcastMaxListeners,
                                           timeoutMs);
        return BroadcastSucceeded(result, error);
    }

    bool AmsiIpcRuntime::IsRunning() const
    {
        return m_impl && m_impl->running;
    }

}
