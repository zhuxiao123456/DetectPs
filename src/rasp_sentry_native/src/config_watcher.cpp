#include "config_watcher.h"
#include "amsi_config_broadcaster.h"
#include "amsi_rule_provider.h"
#include "sentry_log.h"
#include <shlwapi.h>
#include <algorithm>
#include <string>

// ── Helpers ───────────────────────────────────────────────────────────────────

static std::wstring Utf8ToWide(const std::string& s)
{
    if (s.empty()) return {};
    int len = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    std::wstring out(len, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &out[0], len);
    if (!out.empty() && out.back() == 0) out.pop_back();
    return out;
}

std::string ConfigWatcher::DirOf(const std::string& filePath)
{
    size_t pos = filePath.find_last_of("/\\");
    return (pos == std::string::npos) ? "." : filePath.substr(0, pos);
}

// ── ConfigWatcher ─────────────────────────────────────────────────────────────

ConfigWatcher::ConfigWatcher(std::string rulesPath, amsi_ipc::IAmsiRuleProvider* ruleProvider)
    : m_rulesPath(std::move(rulesPath))
    , m_rulesDir(DirOf(m_rulesPath))
    , m_ruleProvider(ruleProvider)
{
    InitializeCriticalSection(&m_debounceLock);
}

ConfigWatcher::~ConfigWatcher()
{
    if (m_running.load()) Stop();
    DeleteCriticalSection(&m_debounceLock);
}

void ConfigWatcher::Start()
{
    m_stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    m_running.store(true);

    // Thread 1: watch the rules JSON file (non-recursive, exact filename match)
    DWORD tid = 0;
    m_rulesFileThread = CreateThread(nullptr, 0, WatchRulesFileProc, this, 0, &tid);

    // Thread 2: watch the rules/lua directory recursively for *.lua changes
    m_luaDirThread = CreateThread(nullptr, 0, WatchLuaDirProc, this, 0, &tid);
}

void ConfigWatcher::Stop()
{
    m_running.store(false);
    if (m_stopEvent) SetEvent(m_stopEvent);

    // Cancel any pending debounce timer and wait for in-progress callback to finish.
    EnterCriticalSection(&m_debounceLock);
    if (m_debounceTimer)
    {
        DeleteTimerQueueTimer(nullptr, m_debounceTimer, INVALID_HANDLE_VALUE);
        m_debounceTimer = nullptr;
    }
    LeaveCriticalSection(&m_debounceLock);

    if (m_rulesFileThread != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(m_rulesFileThread, 3000);
        CloseHandle(m_rulesFileThread);
        m_rulesFileThread = INVALID_HANDLE_VALUE;
    }
    if (m_luaDirThread != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(m_luaDirThread, 3000);
        CloseHandle(m_luaDirThread);
        m_luaDirThread = INVALID_HANDLE_VALUE;
    }
    if (m_stopEvent)
    {
        CloseHandle(m_stopEvent);
        m_stopEvent = nullptr;
    }
}

// ── Watcher threads ───────────────────────────────────────────────────────────

DWORD WINAPI ConfigWatcher::WatchRulesFileProc(LPVOID param)
{
    auto* self = static_cast<ConfigWatcher*>(param);
    // Watch the directory containing rasp_rules.json; filter by exact filename below.
    std::wstring dir    = Utf8ToWide(self->m_rulesDir);
    self->WatchDirectory(dir, nullptr, false);
    return 0;
}

DWORD WINAPI ConfigWatcher::WatchLuaDirProc(LPVOID param)
{
    auto* self = static_cast<ConfigWatcher*>(param);
    // Watch <rulesDir>\rules  recursively for any *.lua change.
    std::wstring luaDir = Utf8ToWide(self->m_rulesDir) + L"\\rules";
    self->WatchDirectory(luaDir, L"*.lua", true);
    return 0;
}

void ConfigWatcher::WatchDirectory(const std::wstring& dir, const wchar_t* filter, bool recursive)
{
    HANDLE hDir = CreateFileW(dir.c_str(),
                              FILE_LIST_DIRECTORY,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING,
                              FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED,
                              nullptr);
    if (hDir == INVALID_HANDLE_VALUE)
    {
        // Directory may not exist yet (e.g., rules/ subdir).  Silently return.
        return;
    }

    OVERLAPPED ov   = {};
    ov.hEvent       = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    char buf[8192];

    while (m_running.load())
    {
        ResetEvent(ov.hEvent);
        DWORD bytesRet = 0;
        BOOL ok = ReadDirectoryChangesW(
            hDir, buf, static_cast<DWORD>(sizeof(buf)),
            recursive ? TRUE : FALSE,
            FILE_NOTIFY_CHANGE_LAST_WRITE | FILE_NOTIFY_CHANGE_SIZE | FILE_NOTIFY_CHANGE_FILE_NAME,
            nullptr, &ov, nullptr);

        if (!ok)
        {
            // On overflow (ERROR_NOTIFY_ENUM_DIR) trigger a conservative reload.
            if (GetLastError() == ERROR_NOTIFY_ENUM_DIR)
                OnChanged();
            Sleep(1000);
            continue;
        }

        HANDLE waitHandles[2] = { ov.hEvent, m_stopEvent };
        DWORD  waitResult = WaitForMultipleObjects(2, waitHandles, FALSE, INFINITE);
        if (waitResult != WAIT_OBJECT_0) break;  // stop event fired or error

        if (!GetOverlappedResult(hDir, &ov, &bytesRet, FALSE)) continue;
        if (bytesRet == 0) { OnChanged(); continue; }  // overflow

        const FILE_NOTIFY_INFORMATION* fni =
            reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(buf);
        bool relevant = false;
        while (fni)
        {
            std::wstring fileName(fni->FileName, fni->FileNameLength / sizeof(wchar_t));

            if (filter == nullptr)
            {
                // Rules-file watcher: check for rasp_rules.json specifically
                relevant = (PathMatchSpecW(fileName.c_str(), L"rasp_rules.json") == TRUE);
            }
            else
            {
                relevant = (PathMatchSpecW(fileName.c_str(), filter) == TRUE);
            }

            if (relevant) break;
            if (fni->NextEntryOffset == 0) break;
            fni = reinterpret_cast<const FILE_NOTIFY_INFORMATION*>(
                      reinterpret_cast<const char*>(fni) + fni->NextEntryOffset);
        }

        if (relevant) OnChanged();
    }

    CloseHandle(ov.hEvent);
    CloseHandle(hDir);
}

// ── Debounce ──────────────────────────────────────────────────────────────────

void ConfigWatcher::OnChanged()
{
    SentryLog_Info("ConfigWatcher", "File change detected — debouncing %lums", kDebounceMs);

    EnterCriticalSection(&m_debounceLock);
    // Cancel any pending timer, then create a fresh one-shot timer.
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

VOID CALLBACK ConfigWatcher::DebounceCallback(PVOID param, BOOLEAN /*fired*/)
{
    static_cast<ConfigWatcher*>(param)->FireDebounced();
}

void ConfigWatcher::FireDebounced()
{
    SentryLog_Info("ConfigWatcher", "Debounce expired — invalidating cache and broadcasting reload");
    InvalidateRuleCache();
    BroadcastReload();
}

void ConfigWatcher::InvalidateRuleCache()
{
    if (m_ruleProvider) {
        m_ruleProvider->InvalidateRuleCache();
    }
}

void ConfigWatcher::InvalidateRuleCacheForTest()
{
    InvalidateRuleCache();
}

// ── Broadcast ─────────────────────────────────────────────────────────────────

void ConfigWatcher::BroadcastReload()
{
    SentryLog_Info("ConfigWatcher", "Broadcasting 0x01 on amsi_detect_config");
    const amsi_ipc::AmsiConfigBroadcaster broadcaster(kConfigPipeName);
    const auto result = broadcaster.Broadcast(amsi_ipc::AmsiControlSignal::Reload,
                                              kMaxListeners,
                                              kBroadcastTimeout);
    if (result.lastError != ERROR_SUCCESS) {
        SentryLog_Info("ConfigWatcher",
                       "Broadcast stopped (GLE=%lu, reached=%d)",
                       static_cast<DWORD>(result.lastError),
                       result.reached);
    }
    SentryLog_Info("ConfigWatcher", "Broadcast complete — reached %d listener(s)", result.reached);
}
