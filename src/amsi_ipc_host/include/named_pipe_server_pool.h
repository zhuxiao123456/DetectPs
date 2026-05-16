#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <string>
#include <vector>

namespace amsi_ipc {

class INamedPipeClientHandler {
public:
    virtual ~INamedPipeClientHandler() = default;
    virtual void HandleClient(HANDLE pipe) = 0;
};

class NamedPipeServerPool {
public:
    NamedPipeServerPool(std::wstring pipeName,
                        int threadCount,
                        INamedPipeClientHandler& handler,
                        DWORD outBufferBytes = 65536,
                        DWORD inBufferBytes = 256,
                        DWORD openMode = PIPE_ACCESS_DUPLEX,
                        DWORD dummyClientAccess = GENERIC_READ | GENERIC_WRITE);
    ~NamedPipeServerPool();

    NamedPipeServerPool(const NamedPipeServerPool&) = delete;
    NamedPipeServerPool& operator=(const NamedPipeServerPool&) = delete;

    bool Start();
    void Stop();

private:
    static DWORD WINAPI ThreadProc(LPVOID param);
    void ServerLoop();

    std::wstring pipeName_;
    int threadCount_ = 0;
    INamedPipeClientHandler& handler_;
    DWORD outBufferBytes_ = 0;
    DWORD inBufferBytes_ = 0;
    DWORD openMode_ = PIPE_ACCESS_DUPLEX;
    DWORD dummyClientAccess_ = GENERIC_READ | GENERIC_WRITE;
    std::atomic<bool> running_{false};
    std::vector<HANDLE> threads_;
};

} // namespace amsi_ipc
