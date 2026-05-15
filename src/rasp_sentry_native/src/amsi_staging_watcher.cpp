#include "amsi_staging_watcher.h"
#include "amsi_config_broadcaster.h"
#include "sentry_log.h"
#include <string>

// ── Wide/narrow helpers ───────────────────────────────────────────────────────

static std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &out[0], len);
    if (!out.empty() && out.back() == 0) out.pop_back();
    return out;
}

static std::string WideToUtf8(const std::wstring& s)
{
    if (s.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, nullptr, 0, nullptr, nullptr);
    std::string out(len, 0);
    WideCharToMultiByte(CP_UTF8, 0, s.c_str(), -1, &out[0], len, nullptr, nullptr);
    if (!out.empty() && out.back() == 0) out.pop_back();
    return out;
}

// ── AmsiStagingWatcher ────────────────────────────────────────────────────────

AmsiStagingWatcher::AmsiStagingWatcher(std::string stagingDir,
                                       EventCollector::DrainAckQueue* drainQueue)
    : m_stagingDir(std::move(stagingDir))
    , m_drainQueue(drainQueue)
{
    InitializeCriticalSection(&m_debounceLock);
}

AmsiStagingWatcher::~AmsiStagingWatcher()
{
    if (m_running.load()) Stop();
    DeleteCriticalSection(&m_debounceLock);
}

void AmsiStagingWatcher::Start()
{
    // Ensure staging directory exists
    if (!CreateDirectoryA(m_stagingDir.c_str(), nullptr) &&
        GetLastError() != ERROR_ALREADY_EXISTS)
    {
        SentryLog_Error("AmsiStagingWatcher", "Cannot create staging directory: %s (GLE=%lu)",
                        m_stagingDir.c_str(), GetLastError());
        return;
    }

    m_stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    m_running.store(true);

    DWORD tid = 0;
    m_watchThread = CreateThread(nullptr, 0, WatchThreadProc, this, 0, &tid);
    if (m_watchThread == nullptr || m_watchThread == INVALID_HANDLE_VALUE)
        SentryLog_Error("AmsiStagingWatcher", "Failed to create watch thread (GLE=%lu)", GetLastError());

    SentryLog_Info("AmsiStagingWatcher", "Watching for %s in: %s",
                   kWatchFileName, m_stagingDir.c_str());
}

void AmsiStagingWatcher::Stop()
{
    m_running.store(false);
    if (m_stopEvent) SetEvent(m_stopEvent);

    EnterCriticalSection(&m_debounceLock);
    if (m_debounceTimer)
    {
        // INVALID_HANDLE_VALUE = wait for any in-progress callback to complete
        DeleteTimerQueueTimer(nullptr, m_debounceTimer, INVALID_HANDLE_VALUE);
        m_debounceTimer = nullptr;
    }
    LeaveCriticalSection(&m_debounceLock);

    if (m_watchThread != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(m_watchThread, 3000);
        CloseHandle(m_watchThread);
        m_watchThread = INVALID_HANDLE_VALUE;
    }
    if (m_stopEvent)
    {
        CloseHandle(m_stopEvent);
        m_stopEvent = nullptr;
    }
}

// ── Watch thread ──────────────────────────────────────────────────────────────

DWORD WINAPI AmsiStagingWatcher::WatchThreadProc(LPVOID param)
{
    static_cast<AmsiStagingWatcher*>(param)->WatchLoop();
    return 0;
}

void AmsiStagingWatcher::WatchLoop()
{
    std::wstring wStagingDir = Utf8ToWide(m_stagingDir);

    HANDLE hDir = CreateFileW(wStagingDir.c_str(),
                              FILE_LIST_DIRECTORY,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                              nullptr);
    if (hDir == INVALID_HANDLE_VALUE)
    {
        SentryLog_Error("AmsiStagingWatcher", "Cannot open staging dir for watching: %s (GLE=%lu)",
                        m_stagingDir.c_str(), GetLastError());
        return;
    }

    OVERLAPPED ov   = {};
    ov.hEvent       = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    char buf[4096];

    while (m_running.load())
    {
        ResetEvent(ov.hEvent);
        DWORD bytesRet = 0;
        ReadDirectoryChangesW(hDir, buf, static_cast<DWORD>(sizeof(buf)),
                              FALSE,
                              FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_FILE_NAME,
                              nullptr, &ov, nullptr);

        HANDLE waitHandles[2] = { ov.hEvent, m_stopEvent };
        DWORD  waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
        if (waitResult != WAIT_OBJECT_0) break;

        if (!GetOverlappedResult(hDir, &ov, &bytesRet, FALSE)) continue;
        if (bytesRet == 0) { OnChanged(); continue; }

        const FILE_NOTIFY_INFORMATION* fni =
            reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(buf);
        while (fni)
        {
            std::wstring fname(fni->FileName, fni->FileNameLength / sizeof(wchar_t));
            // Case-insensitive compare for "rasp_mod_amsi.dll"
            if (_wcsicmp(fname.c_str(), L"rasp_mod_amsi.dll") == 0)
            {
                OnChanged();
                break;
            }
            if (fni->NextEntryOffset == 0) break;
            fni = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(
                      reinterpret_cast<const char*>(fni) + fni->NextEntryOffset);
        }
    }

    CloseHandle(ov.hEvent);
    CloseHandle(hDir);
}

// ── Debounce ──────────────────────────────────────────────────────────────────

void AmsiStagingWatcher::OnChanged()
{
    SentryLog_Info("AmsiStagingWatcher", "Staged DLL detected — debouncing %dms", kDebounceMs);

    EnterCriticalSection(&m_debounceLock);
    if (m_debounceTimer)
    {
        DeleteTimerQueueTimer(nullptr, m_debounceTimer, nullptr);
        m_debounceTimer = nullptr;
    }
    CreateTimerQueueTimer(&m_debounceTimer, nullptr,
                          DebounceCallback, this,
                          kDebounceMs, 0,
                          WT_EXECUTEONLYONCE);
    LeaveCriticalSection(&m_debounceLock);
}

VOID CALLBACK AmsiStagingWatcher::DebounceCallback(PVOID param, BOOLEAN /*fired*/)
{
    static_cast<AmsiStagingWatcher*>(param)->TriggerUpdate();
}

// ── Update orchestration ──────────────────────────────────────────────────────

void AmsiStagingWatcher::TriggerUpdate()
{
    std::wstring wStagingDir = Utf8ToWide(m_stagingDir);
    std::wstring stagedPath  = wStagingDir + L"\\" + L"rasp_mod_amsi.dll";
    std::wstring installedPath = ReadInstalledPath();

    if (installedPath.empty())
    {
        SentryLog_Warn("AmsiStagingWatcher",
                       "Cannot read installed DLL path from registry (CLSID %ls) — aborting update",
                       kAmsiClsid);
        return;
    }

    if (GetFileAttributesW(stagedPath.c_str()) == INVALID_FILE_ATTRIBUTES)
    {
        SentryLog_Warn("AmsiStagingWatcher", "Staged file no longer present: %s",
                       WideToUtf8(stagedPath).c_str());
        return;
    }

    SentryLog_Info("AmsiStagingWatcher",
                   "Starting update: staged=%s  installed=%s",
                   WideToUtf8(stagedPath).c_str(),
                   WideToUtf8(installedPath).c_str());

    int reached = BroadcastUnload();

    bool ackReceived = WaitForDrainAck(reached, kDrainTimeoutMs);
    if (!ackReceived)
    {
        SentryLog_Info("AmsiStagingWatcher",
                       "Drain ACK not received in time — waiting %dms as fallback", kDrainWaitMs);
        Sleep(kDrainWaitMs);
    }

    // Primary: shadow rename (safe for memory-mapped DLLs).
    if (TryShadowReplace(stagedPath, installedPath))
    {
        SentryLog_Info("AmsiStagingWatcher",
                       "DLL replaced via shadow rename — next AMSI scan will load the new binary");
        return;
    }

    // Secondary: retry MoveFileEx(REPLACE_EXISTING) for up to kRetryTimeoutMs.
    SentryLog_Warn("AmsiStagingWatcher",
                   "Shadow rename failed — retrying MoveFileEx for up to %ds",
                   kRetryTimeoutMs / 1000);
    bool replaced = false;
    int  elapsed  = 0;
    while (elapsed < kRetryTimeoutMs)
    {
        if (TryMoveFile(stagedPath, installedPath))
        {
            replaced = true;
            SentryLog_Info("AmsiStagingWatcher",
                           "Replaced via MoveFileEx after %dms", elapsed);
            break;
        }
        Sleep(kRetryIntervalMs);
        elapsed += kRetryIntervalMs;
    }

    if (!replaced)
    {
        SentryLog_Warn("AmsiStagingWatcher",
                       "MoveFileEx still failing after %dms (GLE=%lu) — scheduling replacement at reboot",
                       kRetryTimeoutMs, GetLastError());
        ScheduleReboot(stagedPath, installedPath);
    }
}

// ── Registry ──────────────────────────────────────────────────────────────────

std::wstring AmsiStagingWatcher::ReadInstalledPath()
{
    std::wstring keyPath = std::wstring(L"Software\\Classes\\CLSID\\") +
                           kAmsiClsid + L"\\InprocServer32";
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS)
        return {};

    wchar_t valueBuf[MAX_PATH] = {};
    DWORD   valueSize          = sizeof(valueBuf);
    DWORD   type               = 0;
    LONG r = RegQueryValueExW(hKey, nullptr, nullptr, &type,
                               reinterpret_cast<LPBYTE>(valueBuf), &valueSize);
    RegCloseKey(hKey);
    if (r != ERROR_SUCCESS || (type != REG_SZ && type != REG_EXPAND_SZ)) return {};
    return std::wstring(valueBuf);
}

// ── Broadcast unload (0x02) ───────────────────────────────────────────────────

int AmsiStagingWatcher::BroadcastUnload()
{
    SentryLog_Info("AmsiStagingWatcher",
                   "Broadcasting 0x02 unload signal on pipe amsi_detect_config");
    const amsi_ipc::AmsiConfigBroadcaster broadcaster(kConfigPipeName);
    const auto result = broadcaster.Broadcast(amsi_ipc::AmsiControlSignal::Unload,
                                              kMaxListeners,
                                              kBroadcastTimeout);
    SentryLog_Info("AmsiStagingWatcher",
                   "Unload broadcast complete — reached %d provider(s)", result.reached);
    return result.reached;
}

// ── Drain ACK wait ────────────────────────────────────────────────────────────

bool AmsiStagingWatcher::WaitForDrainAck(int expectedCount, int timeoutMs)
{
    if (expectedCount <= 0) return true;

    SentryLog_Info("AmsiStagingWatcher",
                   "Waiting for drain ACK from %d provider(s)...", expectedCount);

    int received = 0, elapsed = 0;
    constexpr int pollMs = 100;
    while (elapsed < timeoutMs && received < expectedCount)
    {
        std::string item;
        while (m_drainQueue->TryDequeue(item))
        {
            ++received;
            SentryLog_Info("AmsiStagingWatcher",
                           "Drain ACK %d/%d: %s", received, expectedCount, item.c_str());
        }
        if (received < expectedCount)
        {
            Sleep(pollMs);
            elapsed += pollMs;
        }
    }

    bool ok = (received >= expectedCount);
    SentryLog_Info("AmsiStagingWatcher",
                   "WaitForDrainAck: %d/%d in %dms — %s",
                   received, expectedCount, elapsed, ok ? "OK" : "TIMEOUT");
    return ok;
}

// ── Shadow rename & fallbacks ─────────────────────────────────────────────────

bool AmsiStagingWatcher::TryShadowReplace(const std::wstring& staged,
                                           const std::wstring& installed)
{
    std::wstring backup = installed + L".bak";

    // Step 1: rename installed -> .bak (succeeds even if memory-mapped)
    if (!MoveFileExW(installed.c_str(), backup.c_str(),
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED))
    {
        SentryLog_Warn("AmsiStagingWatcher",
                       "Shadow rename failed (GLE=%lu): %s -> .bak",
                       GetLastError(), WideToUtf8(installed).c_str());
        return false;
    }
    SentryLog_Info("AmsiStagingWatcher",
                   "Shadow renamed: %s -> %s",
                   WideToUtf8(installed).c_str(), WideToUtf8(backup).c_str());

    // Step 2: copy staged DLL to original path (fresh file ID — never mapped)
    if (!CopyFileW(staged.c_str(), installed.c_str(), FALSE))
    {
        DWORD gle = GetLastError();
        SentryLog_Warn("AmsiStagingWatcher",
                       "CopyFile failed (GLE=%lu) — restoring backup", gle);
        MoveFileExW(backup.c_str(), installed.c_str(), MOVEFILE_REPLACE_EXISTING);
        return false;
    }
    SentryLog_Info("AmsiStagingWatcher",
                   "New DLL placed at: %s", WideToUtf8(installed).c_str());

    // Step 3: delete staged source (non-fatal)
    if (!DeleteFileW(staged.c_str()))
        SentryLog_Warn("AmsiStagingWatcher",
                       "Could not delete staged file (GLE=%lu)", GetLastError());

    return true;
}

bool AmsiStagingWatcher::TryMoveFile(const std::wstring& src, const std::wstring& dst)
{
    return MoveFileExW(src.c_str(), dst.c_str(),
                       MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED) != FALSE;
}

void AmsiStagingWatcher::ScheduleReboot(const std::wstring& src, const std::wstring& dst)
{
    BOOL ok = MoveFileExW(src.c_str(), dst.c_str(),
                          MOVEFILE_DELAY_UNTIL_REBOOT | MOVEFILE_REPLACE_EXISTING);
    if (ok)
        SentryLog_Info("AmsiStagingWatcher",
                       "Replacement scheduled at next reboot: %s", WideToUtf8(dst).c_str());
    else
        SentryLog_Error("AmsiStagingWatcher",
                        "MOVEFILE_DELAY_UNTIL_REBOOT also failed (GLE=%lu)", GetLastError());
}
