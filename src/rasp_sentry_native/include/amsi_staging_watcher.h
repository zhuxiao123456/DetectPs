#pragma once
// amsi_staging_watcher.h — Watches staging directory for rasp_mod_amsi.dll.
// On detection: 500ms debounce → broadcast 0x02 unload signal →
// wait for drain-ack → shadow rename DLL replacement.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <atomic>
#include <string>
#include "event_collector.h"  // for DrainAckQueue

class AmsiStagingWatcher
{
public:
    // CLSID must match DEFINE_GUID in rasp_mod_amsi.h
    static constexpr const wchar_t* kAmsiClsid       = L"{C0FFEE02-0000-0000-0000-000000000002}";
    static constexpr const wchar_t* kConfigPipeName  = L"\\\\.\\pipe\\amsi_detect_config";
    static constexpr const char*    kWatchFileName    = "rasp_mod_amsi.dll";
    static constexpr DWORD          kDebounceMs       = 500;
    static constexpr int            kDrainWaitMs      = 1000;
    static constexpr int            kDrainTimeoutMs   = 5000;
    static constexpr int            kRetryTimeoutMs   = 30000;
    static constexpr int            kRetryIntervalMs  = 1000;
    static constexpr int            kMaxListeners     = 32;
    static constexpr DWORD          kBroadcastTimeout = 500;

    AmsiStagingWatcher(std::string stagingDir,
                       EventCollector::DrainAckQueue* drainQueue);
    ~AmsiStagingWatcher();

    void Start();
    void Stop();

private:
    std::string                    m_stagingDir;
    EventCollector::DrainAckQueue* m_drainQueue;
    std::atomic<bool>              m_running{false};

    HANDLE                         m_watchThread  = INVALID_HANDLE_VALUE;
    HANDLE                         m_stopEvent    = nullptr;

    CRITICAL_SECTION               m_debounceLock;
    HANDLE                         m_debounceTimer = nullptr;

    static DWORD WINAPI WatchThreadProc(LPVOID param);
    void WatchLoop();
    void OnChanged();
    void TriggerUpdate();

    std::wstring ReadInstalledPath();
    int          BroadcastUnload();
    bool         WaitForDrainAck(int expectedCount, int timeoutMs);
    bool         TryShadowReplace(const std::wstring& staged, const std::wstring& installed);
    bool         TryMoveFile(const std::wstring& src, const std::wstring& dst);
    void         ScheduleReboot(const std::wstring& src, const std::wstring& dst);

    static VOID CALLBACK DebounceCallback(PVOID param, BOOLEAN fired);
};
