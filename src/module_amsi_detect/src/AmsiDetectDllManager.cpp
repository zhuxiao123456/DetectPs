//
// Created by y00969037 on 2026/5/21.
//

#include "AmsiDetectDllManager.h"

#include <windows.h>
#include <algorithm>
#include <utility>

#include "ExecuteCmdUtils.h"
#include "StrUtils.h"
#include "FileUtils.h"

#include "AmsiDetectGlobalParam.h"
#include "AmsiGlobalConf.h"

namespace Engine {

    using namespace SDK;
    using namespace AmsiDetect;

    namespace {
        /**
         * 生成类似upgrade-hash的前16位
         * @param stagingDllHash  哈希值
         * @return  升级状态版本,方便dll侧识别这是一次新的升级窗口
         */
        std::string BuildUpgradeStateVersion(const std::string &stagingDllHash)
        {
            if (stagingDllHash.empty()) {
                return "upgrade-unknown";
            }
            return "upgrade-" + stagingDllHash.substr(0, std::min<size_t>(stagingDllHash.size(), 16));
        }
    }
    AmsiDetectDllManager::AmsiDetectDllManager(const std::string &amsiDllFilePath)
        : m_amsiDllFilePath(amsiDllFilePath)
    {
    }

    bool AmsiDetectDllManager::RegisterAmsiProvider()
    {
        std::vector<std::string> args;
        args.emplace_back("/s");
        args.emplace_back(m_amsiDllFilePath);
        int exitCode = 0;
        int rv = ExecuteCmdUtils::ExecuteCmd("regsvr32", args, exitCode);
        if(!IS_EXEC_SUCCESS(rv)) {
            ErrorLog(GetLoggerPtr(), "Exec register amsi cmd failed.");
            return false;
        }
        InfoLog(GetLoggerPtr(), "Register amsi success.");
        return true;
    }

    bool AmsiDetectDllManager::UnregisterAmsiProvider()
    {
        std::vector<std::string> args;
        args.emplace_back("/s");
        args.emplace_back("/u");
        args.emplace_back(m_amsiDllFilePath);
        int exitCode = 0;
        int rv = ExecuteCmdUtils::ExecuteCmd("regsvr32", args, exitCode);
        if(!IS_EXEC_SUCCESS(rv)) {
            ErrorLog(GetLoggerPtr(), "Exec unregister amsi cmd failed.");
            return false;
        }
        InfoLog(GetLoggerPtr(), "Unregister amsi success.");
        return true;
    }

    // 更新dll（返回详细状态码）.
    int AmsiDetectDllManager::UpdateAmsiDll(const std::string &stagingDllPath, std::unique_ptr<AmsiIpcRuntime> &m_amsiIpcRuntime)
    {
        return UpdateAmsiDllEx(stagingDllPath, m_amsiIpcRuntime).code;
    }

    AmsiDetectDllManager::AmsiDllUpdateResult AmsiDetectDllManager::UpdateAmsiDllEx(
            const std::string &stagingDllPath,
            std::unique_ptr<AmsiIpcRuntime> &m_amsiIpcRuntime)
    {
        AmsiDllUpdateResult result;

        std::string usingDllHash;
        if (FileUtils::GetFileSha256(m_amsiDllFilePath, usingDllHash) != 0) {
            ErrorLogf1(GetLoggerPtr(), "Failed to get (%s) hash.", m_amsiDllFilePath);
            result.code = UPDATE_FAILED;
            return result;
        }
        result.installedDllHash = usingDllHash;

        std::string stagingDllHash;
        if (FileUtils::GetFileSha256(stagingDllPath, stagingDllHash) != 0) {
            ErrorLogf1(GetLoggerPtr(), "Failed to get (%s) hash.", stagingDllPath);
            result.code = UPDATE_FAILED;
            return result;
        }
        result.targetDllHash = stagingDllHash;

        if (usingDllHash == stagingDllHash) {
            InfoLogf3(GetLoggerPtr(), "(%s) (%s) hash(%s) is consistent, not need update.", m_amsiDllFilePath, stagingDllPath, usingDllHash);
            result.code = UPDATE_SUCCESS;
            result.dllChanged = false;
            return result;
        }

        InfoLogf4(GetLoggerPtr(), "(%s)-hash(%s) (%s)-hash(%s) is not consistent, start update...", m_amsiDllFilePath, usingDllHash, stagingDllPath, stagingDllHash);

        bool enteredUnloadingState = false;
        if (m_amsiIpcRuntime != nullptr) {
            std::string error;
            const std::string stateVersion = BuildUpgradeStateVersion(stagingDllHash);
            if (!m_amsiIpcRuntime->EnterUpgradeUnloadingState(stateVersion, stagingDllHash, error)) {
                WarningLogf1(GetLoggerPtr(), "Enter amsi upgrade unloading state failed: %s.", error);
            } else {
                enteredUnloadingState = true;
                InfoLogf1(GetLoggerPtr(), "Amsi upgrade unloading state entered: %s.", stateVersion);
            }
            InfoLog(GetLoggerPtr(), "Amsi upgrade unloading state published");
            Sleep(AmsiGlobalConfRef.GetUnloadSettleMs());
        }

        std::wstring wStagedPath = StrUtils::Utf8ToUtf16(stagingDllPath);
        std::wstring wInstalledPath = StrUtils::Utf8ToUtf16(m_amsiDllFilePath);
        // 优先使用影子重命名替换DLL.
        if (TryShadowReplace(wStagedPath, wInstalledPath)) {
            InfoLog(GetLoggerPtr(), "DLL updated successfully via shadow rename - next AMSI scan will load the new binary.");
            result.code = UPDATE_SUCCESS_REPLACE;
            result.dllChanged = true;
            return result;
        }

        //  影子重命名失败，重试 MoveFileEx.
        WarningLog(GetLoggerPtr(), "Shadow rename failed - retrying MoveFileEx for up to 30s.");
        int moveResult = TryMoveFile(wStagedPath, wInstalledPath);
        if (moveResult >= 0) {
            InfoLogf1(GetLoggerPtr(), "DLL updated successfully via MoveFileEx %d ms.", moveResult);
            result.code = UPDATE_SUCCESS_MOVE;
            result.dllChanged = true;
            return result;
        }

        // 所有更新方法都失败，安排重启替换.
        InfoLog(GetLoggerPtr(), "All update methods failed - scheduling reboot replacement.");
        if (ScheduleReboot(wStagedPath, wInstalledPath)) {
            result.code = UPDATE_SUCCESS_REBOOT;
            result.dllChanged = true;
            return result;
        } else {
            ErrorLog (GetLoggerPtr(), "Reboot scheduling also failed.");
            if (enteredUnloadingState && m_amsiIpcRuntime != nullptr) {
                std::string restoreError;
                if (!m_amsiIpcRuntime->RestorePreUpgradeSnapshot(restoreError)) {
                    WarningLogf1(GetLoggerPtr(), "Restore amsi ipc running snapshot after dll update failure failed: %s.", restoreError);
                }
            }
            result.code = UPDATE_FAILED;
            return result;
        }
    }

    bool AmsiDetectDllManager::TryShadowReplace(const std::wstring &staged, const std::wstring &installed)
    {
        std::wstring backup = installed + L".bak";

        // 步骤1：重命名已安装DLL为.bak.
        if (!MoveFileExW(installed.c_str(), backup.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED)) {
            ErrorLogf2(GetLoggerPtr(), "Shadow rename step 1 failed (GLE=%lu): %s -> .bak", GetLastError(), StrUtils::Utf16ToUtf8(installed));
            return false;
        }
        InfoLogf2(GetLoggerPtr(), "Shadow renamed step 1: %s -> %s success.", StrUtils::Utf16ToUtf8(installed), StrUtils::Utf16ToUtf8(backup));

        // 步骤2：复制新DLL到原路径.
        if (!CopyFileW(staged.c_str(), installed.c_str(), FALSE)) {
            ErrorLogf3(GetLoggerPtr(), "Shadow rename step 2 failed - copy (%s) to (%s) failed (GLE=%lu), restoring backup", StrUtils::Utf16ToUtf8(staged), StrUtils::Utf16ToUtf8(installed), GetLastError());
            // 尝试恢复备份.
            if (!MoveFileExW(backup.c_str(), installed.c_str(), MOVEFILE_REPLACE_EXISTING)) {
                ErrorLogf3(GetLoggerPtr(), "Restore backup (%s) to (%s) failed (GLE=%lu)", StrUtils::Utf16ToUtf8(backup), StrUtils::Utf16ToUtf8(installed), GetLastError());
            }
            return false;
        }
        InfoLogf2(GetLoggerPtr(), "Shadow renamed step 2: %s -> %s success", StrUtils::Utf16ToUtf8(staged), StrUtils::Utf16ToUtf8(installed));

        // 步骤3：删除暂存文件（非致命，失败不影响更新结果）.
        if (!DeleteFileW(staged.c_str())) {
            WarningLogf2(GetLoggerPtr(), "Could not delete staged file(%s) (GLE=%lu)", StrUtils::Utf16ToUtf8(staged), GetLastError());
        }

        return true;  // 影子重命名成功.
    }

    int AmsiDetectDllManager::TryMoveFile(const std::wstring &src, const std::wstring &dst)
    {
        constexpr int  kRetryTimeoutMs = 30000;
        constexpr int  kRetryIntervalMs = 1000;
        DWORD elapsed = 0;
        while (elapsed < kRetryTimeoutMs) {
            if (MoveFileExW(src.c_str(), dst.c_str(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED)) {
                return elapsed + 1;  // 返回耗时+1（避免与0冲突）.
            }
            DebugLogf3(GetLoggerPtr(), "MoveFileEx failed (GLE=%lu), retry %dms later, elapsed %dms", GetLastError(), kRetryIntervalMs, elapsed);
            
            Sleep(kRetryIntervalMs);
            elapsed += kRetryIntervalMs;
        }
        
        return -1;  // 移动失败（超时）.
    }

    bool AmsiDetectDllManager::ScheduleReboot(const std::wstring& src, const std::wstring& dst)
    {
        BOOL ok = MoveFileExW(src.c_str(), dst.c_str(), MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING);
        if (ok) {
            InfoLogf2(GetLoggerPtr(), 
                "Replacement scheduled at next reboot: %s -> %s", 
                StrUtils::Utf16ToUtf8(src), StrUtils::Utf16ToUtf8(dst));
            return true;  // 重启安排成功.
        } else {
            ErrorLogf1(GetLoggerPtr(), 
                "MOVE_FILE_DELAY_UNTIL_REBOOT also failed (GLE=%lu)", GetLastError());
            return false;  // 重启安排失败.
        }
    }

}
