#include "named_pipe_server_pool.h"

#include "pipe_security.h"

#include <utility>

namespace amsi_ipc {

NamedPipeServerPool::NamedPipeServerPool(std::wstring pipeName,
                                         int threadCount,
                                         INamedPipeClientHandler& handler,
                                         DWORD outBufferBytes,
                                         DWORD inBufferBytes)
    : pipeName_(std::move(pipeName)),
      threadCount_(threadCount),
      handler_(handler),
      outBufferBytes_(outBufferBytes),
      inBufferBytes_(inBufferBytes)
{
}

NamedPipeServerPool::~NamedPipeServerPool()
{
    Stop();
}

bool NamedPipeServerPool::Start()
{
    if (running_.exchange(true)) {
        return true;
    }

    threads_.assign(static_cast<size_t>(threadCount_), INVALID_HANDLE_VALUE);
    bool ok = true;
    for (int i = 0; i < threadCount_; ++i) {
        DWORD tid = 0;
        threads_[static_cast<size_t>(i)] = CreateThread(nullptr, 0, ThreadProc, this, 0, &tid);
        if (threads_[static_cast<size_t>(i)] == nullptr ||
            threads_[static_cast<size_t>(i)] == INVALID_HANDLE_VALUE) {
            threads_[static_cast<size_t>(i)] = INVALID_HANDLE_VALUE;
            ok = false;
        }
    }
    return ok;
}

void NamedPipeServerPool::Stop()
{
    if (!running_.exchange(false)) {
        return;
    }

    for (int i = 0; i < threadCount_; ++i) {
        HANDLE dummy = CreateFileW(pipeName_.c_str(),
                                   GENERIC_READ | GENERIC_WRITE,
                                   0,
                                   nullptr,
                                   OPEN_EXISTING,
                                   0,
                                   nullptr);
        if (dummy != INVALID_HANDLE_VALUE) {
            CloseHandle(dummy);
        }
    }

    std::vector<HANDLE> valid;
    valid.reserve(threads_.size());
    for (HANDLE thread : threads_) {
        if (thread != INVALID_HANDLE_VALUE && thread != nullptr) {
            valid.push_back(thread);
        }
    }

    if (!valid.empty()) {
        WaitForMultipleObjects(static_cast<DWORD>(valid.size()), valid.data(), TRUE, 3000);
    }

    for (HANDLE& thread : threads_) {
        if (thread != INVALID_HANDLE_VALUE && thread != nullptr) {
            CloseHandle(thread);
        }
        thread = INVALID_HANDLE_VALUE;
    }
}

DWORD WINAPI NamedPipeServerPool::ThreadProc(LPVOID param)
{
    static_cast<NamedPipeServerPool*>(param)->ServerLoop();
    return 0;
}

void NamedPipeServerPool::ServerLoop()
{
    SECURITY_ATTRIBUTES sa = {};
    PACL acl = nullptr;
    const bool haveSa = MakeAuthenticatedUsersSecurity(&sa, &acl);

    while (running_.load()) {
        HANDLE pipe = CreateNamedPipeW(pipeName_.c_str(),
                                       PIPE_ACCESS_DUPLEX,
                                       PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                       threadCount_,
                                       outBufferBytes_,
                                       inBufferBytes_,
                                       0,
                                       haveSa ? &sa : nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(100);
            continue;
        }

        const BOOL connected = ConnectNamedPipe(pipe, nullptr);
        if (!running_.load()) {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            break;
        }
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            CloseHandle(pipe);
            continue;
        }

        handler_.HandleClient(pipe);
        DisconnectNamedPipe(pipe);
        CloseHandle(pipe);
    }

    if (haveSa) {
        FreePipeSecurity(&sa, acl);
    }
}

} // namespace amsi_ipc
