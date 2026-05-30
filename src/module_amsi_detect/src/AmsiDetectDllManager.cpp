//
// Created by y00969037 on 2026/5/21.
//

#include "AmsiDetectDllManager.h"

#include <windows.h>
#include <algorithm>

#include "ExecuteCmdUtils.h"
#include "StrUtils.h"
#include "FileUtils.h"

#include "AmsiDetectGlobalParam.h"
#include "AmsiGlobalConf.h"

namespace Engine {

    using namespace SDK;
    using namespace AmsiDetect;

    namespace {
        const int kUpgradeUnloadBroadcastCycles = 3;
        const uint32_t kUpgradeUnloadBroadcastTimeoutMs = 1000;
        const DWORD kUpgradeUnloadSettleMs = 3000;

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
        std::string usingDllHash;
        if (FileUtils::GetFileSha256(m_amsiDllFilePath, usingDllHash) != 0) {
            ErrorLogf1(GetLoggerPtr(), "Failed to get (%s) hash.", m_amsiDllFilePath);
            return UPDATE_FAILED;
        }
        std::string stagingDllHash;
        if (FileUtils::GetFileSha256(stagingDllPath, stagingDllHash) != 0) {
            ErrorLogf1(GetLoggerPtr(), "Failed to get (%s) hash.", stagingDllPath);
            return UPDATE_FAILED;
        }
        if (usingDllHash == stagingDllHash) {
            InfoLogf3(GetLoggerPtr(), "(%s) (%s) hash(%s) is consistent, not need update.", m_amsiDllFilePath, stagingDllPath, usingDllHash);
            return UPDATE_SUCCESS;
        }

        InfoLogf4(GetLoggerPtr(), "(%s)-hash(%s) (%s)-hash(%s) is not consistent, start update...", m_amsiDllFilePath, usingDllHash, stagingDllPath, stagingDllHash);

        bool enteredUnloadingState = false;
        if (m_amsiIpcRuntime != nullptr) {
            std::string error;
            const std::string stateVersion = BuildUpgradeStateVersion(stagingDllHash);
            if (!m_amsiIpcRuntime->EnterUpgradeUnloadingState(stateVersion, error)) {
                WarningLogf1(GetLoggerPtr(), "Enter amsi upgrade unloading state failed: %s.", error);
            } else {
                enteredUnloadingState = true;
                InfoLogf1(GetLoggerPtr(), "Amsi upgrade unloading state entered: %s.", stateVersion);
            }

            for (int i = 0; i < kUpgradeUnloadBroadcastCycles; ++i) {
                error.clear();
                if (!m_amsiIpcRuntime->Unload(kUpgradeUnloadBroadcastTimeoutMs, error)) {
                    WarningLogf2(GetLoggerPtr(), "Broadcast amsi unload during dll update attempt=%d failed: %s.", i + 1, error);
                }
                const AmsiIpcBroadcastSummary summary = m_amsiIpcRuntime->GetLastBroadcastSummary("unload");
                InfoLogf2(GetLoggerPtr(), "Dll update unload broadcast attempt=%d reached=%lu.",
                          i + 1, static_cast<unsigned long>(summary.reached));
                Sleep(1000);
            }
            Sleep(kUpgradeUnloadSettleMs);
        }

        std::wstring wStagedPath = StrUtils::Utf8ToUtf16(stagingDllPath);
        std::wstring wInstalledPath = StrUtils::Utf8ToUtf16(m_amsiDllFilePath);
        // 优先使用影子重命名替换DLL.
        if (TryShadowReplace(wStagedPath, wInstalledPath)) {
            InfoLog(GetLoggerPtr(), "DLL updated successfully via shadow rename - next AMSI scan will load the new binary.");
            return UPDATE_SUCCESS_REPLACE;  // 影子重命名成功
        }

        //  影子重命名失败，重试 MoveFileEx.
        WarningLog(GetLoggerPtr(), "Shadow rename failed - retrying MoveFileEx for up to 30s.");
        int moveResult = TryMoveFile(wStagedPath, wInstalledPath);
        if (moveResult >= 0) {
            InfoLogf1(GetLoggerPtr(), "DLL updated successfully via MoveFileEx %d ms.", moveResult);
            return UPDATE_SUCCESS_MOVE;  // MoveFileEx成功.
        }

        // 所有更新方法都失败，安排重启替换.
        InfoLog(GetLoggerPtr(), "All update methods failed - scheduling reboot replacement.");
        if (ScheduleReboot(wStagedPath, wInstalledPath)) {
            return UPDATE_SUCCESS_REBOOT;  // 重启后替换成功.
        } else {
            ErrorLog (GetLoggerPtr(), "Reboot scheduling also failed.");
            if (enteredUnloadingState && m_amsiIpcRuntime != nullptr) {
                std::string restoreError;
                if (!m_amsiIpcRuntime->RestorePreUpgradeSnapshot(restoreError)) {
                    WarningLogf1(GetLoggerPtr(), "Restore amsi ipc running snapshot after dll update failure failed: %s.", restoreError);
                }
            }
            return UPDATE_FAILED;  // 完全失败.
        }
    }

    int AmsiDetectDllManager::BroadcastUnloadSignal()
    {
        InfoLog(GetLoggerPtr(), "Broadcasting 0x02 unload signal");

        int reached = 0;
        int i = 0;
        for (; i <AmsiGlobalConfRef.GetBroadcastCount(); ++i) {
            // 等待管道可用.
            if (!WaitNamedPipeW(L"\\\\.\\pipe\\rasp_sentry_config", 500)) {
                InfoLogf1(GetLoggerPtr(), "No more pipe listeners available, broadcast cnt(%d)", i);
                break;  // 没有更多监听器.
            }

            // 连接管道.
            HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\rasp_sentry_config", GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (hPipe == INVALID_HANDLE_VALUE) {
                ErrorLogf1(GetLoggerPtr(), "CreateFileW failed (GLE=%lu)", GetLastError());
                continue;
            }

            // 发送 0x02 卸载信号.
            BYTE signal = 0x02;
            DWORD written = 0;
            if (!WriteFile(hPipe, &signal, 1, &written, nullptr) || written != 1) {
                ErrorLogf1(GetLoggerPtr(), "WriteFile failed (GLE=%lu)", GetLastError());
                CloseHandle(hPipe);
                continue;
            }

            CloseHandle(hPipe);
            ++reached;
        }
        InfoLogf2(GetLoggerPtr(), "Unload broadcast complete - reached %d/%d provider(s)", reached, i);

        return reached;  // 返回成功到达的监听器数量.
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
