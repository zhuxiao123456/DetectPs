#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <string>

class ControlStatusCollector
{
public:
    static constexpr const wchar_t* kPipeName = L"amsi_detect_control_status";
    static constexpr int kThreadCount = 2;

    explicit ControlStatusCollector(std::string logDir);
    ~ControlStatusCollector();

    void Start();
    void Stop();

private:
    std::string m_logDir;
    std::atomic<bool> m_running{false};
    HANDLE m_threads[kThreadCount];
    CRITICAL_SECTION m_fileLock;

    static DWORD WINAPI ThreadProc(LPVOID param);
    void ServerLoop();
    void AppendLine(const std::string& jsonLine);
};
