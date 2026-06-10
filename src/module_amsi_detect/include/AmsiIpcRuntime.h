//
// Created by z00840245 on 2026/5/21.
//

#ifndef CSA_ENGINE_AMSI_IPC_RUNTIME_H
#define CSA_ENGINE_AMSI_IPC_RUNTIME_H

#include <cstdint>
#include <memory>
#include <string>

#include "AmsiDetectGlobalParam.h"
#include "AmsiIpcRuntimeQueue.h"

namespace Engine {
    // 控制运行时的行为开关。包含 RASP 启动校验标志（是否强制要求 dll 存在、是否允许 Lua 库缺失）以及相关的物理路径和有界队列配置对象
    struct AmsiIpcRuntimeConfig {
        bool amsiIpcEnabled = true;
        bool enableRealIpc = true;
        bool useProductionPipes = true;

        std::string dllPath;
        std::string rulePath;
        std::string versionPath;
        std::string luaLibPath;
        std::string version;
    };

    class AmsiIpcRuntime {
    public:
        AmsiIpcRuntime();
        ~AmsiIpcRuntime();

        AmsiIpcRuntime(const AmsiIpcRuntime &) = delete;
        AmsiIpcRuntime &operator=(const AmsiIpcRuntime &) = delete;

        bool Init(const AmsiIpcRuntimeConfig &config, std::string &error);
        bool Start(const AmsiDetect::AmsiRuleSnapshot &snapshot, std::string &error);
        bool Stop(uint32_t timeoutMs, std::string &error);

        bool UpdateRules(const AmsiDetect::AmsiRuleSnapshot &snapshot, std::string &error);
        bool EnterUpgradeUnloadingState(const std::string &stateVersion, const std::string &requiredDllHash, std::string &error);
        bool RestorePreUpgradeSnapshot(std::string &error);
        bool RestorePreUpgradeSnapshotWithDllHash(const std::string &requiredDllHash, std::string &error);

    private:
        struct Impl;
        std::unique_ptr<Impl> m_impl;
    };

}

#endif //CSA_ENGINE_AMSI_IPC_RUNTIME_H
