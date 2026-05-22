//
// Created by Codex on 2026/5/21.
//

#ifndef CSA_ENGINE_AMSI_IPC_RUNTIME_H
#define CSA_ENGINE_AMSI_IPC_RUNTIME_H

#include <cstdint>
#include <memory>
#include <string>

#include "AmsiIpcRuntimeQueue.h"
#include "AmsiRuleSnapshot.h"

namespace Engine {

    struct AmsiIpcRuntimeConfig {
        bool amsiIpcEnabled = true;
        bool enableRealIpc = true;
        bool useProductionPipes = true;
        bool requireAmsiDllFile = true;
        bool requireVersionConf = true;
        bool allowLuaLibMissing = true;

        std::string dllPath;
        std::string rulePath;
        std::string versionPath;
        std::string luaLibPath;
        std::string version;

        AmsiIpcRuntimeQueueConfig queueConfig;
    };

    class AmsiIpcRuntime {
    public:
        AmsiIpcRuntime();
        ~AmsiIpcRuntime();

        AmsiIpcRuntime(const AmsiIpcRuntime &) = delete;
        AmsiIpcRuntime &operator=(const AmsiIpcRuntime &) = delete;

        bool Init(const AmsiIpcRuntimeConfig &config, std::string &error);
        bool Start(const AmsiRuleSnapshot &snapshot, std::string &error);
        bool Stop(uint32_t timeoutMs, std::string &error);

        bool PauseDetection(uint32_t timeoutMs, std::string &error);
        bool UpdateRules(const AmsiRuleSnapshot &snapshot, std::string &error);
        bool Reload(uint32_t timeoutMs, std::string &error);

        bool IsRunning() const;
        AmsiIpcRuntimeStats GetStats() const;

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };

}

#endif //CSA_ENGINE_AMSI_IPC_RUNTIME_H
