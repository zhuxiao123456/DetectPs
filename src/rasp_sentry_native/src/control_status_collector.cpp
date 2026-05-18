#include "control_status_collector.h"
#include "sentry_log.h"

#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <utility>

namespace {

std::int64_t HostReceiveTimeMs()
{
    FILETIME ft;
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER value;
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return static_cast<std::int64_t>(value.QuadPart / 10000ULL);
}

void LogInstanceChange(const rasp_sentry::DllInstanceChange& change)
{
    if (!change.observed) {
        return;
    }

    if (change.created && change.currentState == rasp_sentry::DllInstanceState::Online) {
        SentryLog_Info("DllInstance",
                       "DLL instance online: instanceId=%s pid=%lu",
                       change.instanceId.c_str(),
                       static_cast<unsigned long>(change.pid));
    } else if (change.stateChanged &&
               change.previousState == rasp_sentry::DllInstanceState::Stale &&
               change.currentState == rasp_sentry::DllInstanceState::Online) {
        SentryLog_Info("DllInstance",
                       "DLL instance resumed: instanceId=%s pid=%lu",
                       change.instanceId.c_str(),
                       static_cast<unsigned long>(change.pid));
    } else if (change.stateChanged &&
               change.currentState == rasp_sentry::DllInstanceState::Stale) {
        SentryLog_Info("DllInstance",
                       "DLL instance stale: instanceId=%s pid=%lu",
                       change.instanceId.c_str(),
                       static_cast<unsigned long>(change.pid));
    } else if (change.stateChanged &&
               change.currentState == rasp_sentry::DllInstanceState::Unloaded) {
        SentryLog_Info("DllInstance",
                       "DLL instance unloaded: instanceId=%s pid=%lu",
                       change.instanceId.c_str(),
                       static_cast<unsigned long>(change.pid));
    }

    if (change.ruleLoadBecameSeen) {
        SentryLog_Info("DllInstance",
                       "DLL instance rule-load-seen: instanceId=%s pid=%lu",
                       change.instanceId.c_str(),
                       static_cast<unsigned long>(change.pid));
    }
}

void LogPurgedInstance(const rasp_sentry::DllInstanceChange& change)
{
    if (!change.observed) {
        return;
    }
    SentryLog_Info("DllInstance",
                   "DLL instance purged: instanceId=%s pid=%lu state=%s",
                   change.instanceId.c_str(),
                   static_cast<unsigned long>(change.pid),
                   rasp_sentry::DllInstanceStateName(change.currentState));
}

} // namespace

ControlStatusCollector::ControlStatusCollector(std::string logDir)
    : m_logDir(std::move(logDir)),
      m_statusChannel(*this),
      m_statusPipePool(amsi_ipc::kControlStatusPipeName,
                       kThreadCount,
                       m_statusChannel,
                       0,
                       65536,
                       PIPE_ACCESS_INBOUND,
                       GENERIC_WRITE)
{
    InitializeCriticalSection(&m_fileLock);
}

ControlStatusCollector::~ControlStatusCollector()
{
    Stop();
    DeleteCriticalSection(&m_fileLock);
}

void ControlStatusCollector::Start()
{
    if (m_started) {
        return;
    }
    m_started = true;
    if (!m_statusPipePool.Start()) {
        SentryLog_Error("ControlStatusCollector", "Failed to start one or more control status pipe worker thread(s)");
    }
}

void ControlStatusCollector::Stop()
{
    if (!m_started) {
        return;
    }

    m_statusPipePool.Stop();
    m_started = false;
}

void ControlStatusCollector::OnControlStatusLine(const amsi_ipc::AmsiControlStatusLine& status)
{
    std::string line = status.payload;
    // Preserve legacy ControlStatusCollector behavior exactly: trim only
    // trailing LF, CR, and space before appending non-empty payloads.
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' '))
        line.pop_back();
    if (!line.empty()) {
        const std::int64_t nowMs = HostReceiveTimeMs();
        const rasp_sentry::DllInstanceChange change =
            m_instanceRegistry.ObserveControlStatusPayload(line, nowMs);
        LogInstanceChange(change);
        for (const auto& staleChange : m_instanceRegistry.RefreshStates(nowMs)) {
            LogInstanceChange(staleChange);
        }
        for (const auto& purgedChange : m_instanceRegistry.Purge(nowMs)) {
            LogPurgedInstance(purgedChange);
        }
        AppendLine(line);
        WriteInstanceSnapshot(nowMs);
    }
}

void ControlStatusCollector::AppendLine(const std::string& jsonLine)
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    char dateBuf[16];
    _snprintf_s(dateBuf, sizeof(dateBuf), _TRUNCATE,
                "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);

    std::string path = m_logDir + "\\rasp-control-status-" + dateBuf + ".jsonl";

    EnterCriticalSection(&m_fileLock);
    HANDLE hFile = CreateFileA(path.c_str(),
                               FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        std::string line = jsonLine + "\n";
        DWORD written = 0;
        WriteFile(hFile, line.c_str(), static_cast<DWORD>(line.size()), &written, nullptr);
        CloseHandle(hFile);
    }
    LeaveCriticalSection(&m_fileLock);

    SentryLog_Info("ControlStatusCollector", "Appended control status to %s", path.c_str());
}

void ControlStatusCollector::WriteInstanceSnapshot(std::int64_t nowMs)
{
    std::string path = m_logDir + "\\rasp-dll-instances.json";
    std::string tmpPath = path + ".tmp";
    std::ostringstream snapshot;
    m_instanceRegistry.WriteSnapshotJson(snapshot, nowMs);

    EnterCriticalSection(&m_fileLock);
    bool ok = false;
    {
        std::ofstream output(tmpPath, std::ios::binary | std::ios::trunc);
        output << snapshot.str();
        ok = output.good();
    }
    if (ok) {
        ok = MoveFileExA(tmpPath.c_str(),
                         path.c_str(),
                         MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) != FALSE;
    }
    if (!ok) {
        const DWORD gle = GetLastError();
        DeleteFileA(tmpPath.c_str());
        SentryLog_Error("ControlStatusCollector",
                        "Failed to write DLL instance snapshot to %s (GLE=%lu)",
                        path.c_str(),
                        gle);
    }
    LeaveCriticalSection(&m_fileLock);
}

const rasp_sentry::DllInstanceRegistry& ControlStatusCollector::InstanceRegistry() const
{
    return m_instanceRegistry;
}
