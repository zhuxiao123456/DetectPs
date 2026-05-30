//
// Created by y00969037 on 2026/5/21.
//

#ifndef CSA_ENGINE_AMSI_DETECT_DLL_MANAGER_H
#define CSA_ENGINE_AMSI_DETECT_DLL_MANAGER_H

#include <string>
#include <vector>

#include "AmsiIpcRuntime.h"

namespace Engine {

    class AmsiDetectDllManager {
    public:
        // ===== 返回码定义 =====
        // 成功返回码.
        static constexpr int UPDATE_SUCCESS = 0; // hash一致无需更新.
        static constexpr int UPDATE_SUCCESS_REPLACE = 1;      // 影子重命名成功.
        static constexpr int UPDATE_SUCCESS_MOVE = 2;           // MoveFileEx成功.
        static constexpr int UPDATE_SUCCESS_REBOOT = 3;       // 重启后替换成功.
        // 失败返回码.
        static constexpr int UPDATE_FAILED = -1;  // 通用失败.

        AmsiDetectDllManager(const std::string &amsiDllFilePath);
        ~AmsiDetectDllManager() = default;

        // 注册/注销AMSI.
        bool RegisterAmsiProvider();
        bool UnregisterAmsiProvider();
        
        // 更新dll（返回详细状态码）.
        int UpdateAmsiDll(const std::string &stagingDllPath, std::unique_ptr<AmsiIpcRuntime> &m_amsiIpcRuntime);

    private:
        int BroadcastUnloadSignal();
        bool TryShadowReplace(const std::wstring &staged, const std::wstring &installed);
        int TryMoveFile(const std::wstring &src, const std::wstring &dst);
        bool ScheduleReboot(const std::wstring &src, const std::wstring &dst);

    private:
        // DLL路径.
        std::string m_amsiDllFilePath;
    };

}

#endif //CSA_ENGINE_AMSI_DETECT_DLL_MANAGER_H
