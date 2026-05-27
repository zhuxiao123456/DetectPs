/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * 功能: 基于 Windows 原生 API 的多线程命名管道服务端线程池
 */
#include "../include/NamedPipeServerPool.h"

#include "PipeSecurity.h"

#include <utility>

namespace amsi_ipc {
// 构造函敿 初始化线程池的各项参数，问题: 参数超过了限刿
    NamedPipeServerPool::NamedPipeServerPool(std::wstring pipeName,
                                             int threadCount,
                                             INamedPipeClientHandler &handler,
                                             DWORD outBufferBytes,
                                             DWORD inBufferBytes,
                                             DWORD openMode,
                                             DWORD dummyClientAccess)
            : pipeName_(std::move(pipeName)),
              threadCount_(threadCount),
              handler_(handler),  // 依赖注入。这是一个接口引用，线程池只管建立连接，连上后把句柄交给 handler 去处理具体的业务数据
              outBufferBytes_(outBufferBytes),  // 读写缓冲区大尿
              inBufferBytes_(inBufferBytes),
              openMode_(openMode),
              dummyClientAccess_(dummyClientAccess),
              validConfig_(threadCount > 0) {
    }

    NamedPipeServerPool::~NamedPipeServerPool() {
        Stop();
    }

    bool NamedPipeServerPool::Start() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!validConfig_) {
            return false;
        }

        if (running_.exchange(true)) {
            return true;  // 原子锁防重入, 保证即使多个线程同时调用 Start()，也只会执行一次真正的启动逻辑
        }
        // 分配空间
        threads_.assign(static_cast<size_t>(threadCount_), INVALID_HANDLE_VALUE);
        bool ok = true;
        for (int i = 0; i < threadCount_; ++i) {
            DWORD tid = 0;
            // 创建线程，任意一个失败都会返回false
            threads_[static_cast<size_t>(i)] = CreateThread(nullptr, 0, ThreadProc, this, 0, &tid);
            if (threads_[static_cast<size_t>(i)] == nullptr ||
                threads_[static_cast<size_t>(i)] == INVALID_HANDLE_VALUE) {
                threads_[static_cast<size_t>(i)] = INVALID_HANDLE_VALUE;
                ok = false;
            }
        }
        return ok;
    }

/*
 * 安全、优雅地结束所有工作线程，并回收内核对象
 */
    void NamedPipeServerPool::Stop() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!running_.exchange(false)) {
            return;
        }
        // 通过一个 for 循环，故意调用 CreateFileW 模拟客户端，主动去连接自己的管道 threadCount_ 次。
        // 这会瞬间触发底层的连接事件，唤醒所有阻塞的线程。线程醒来后看到 running_ 已经变成 false，就会乖乖退出循环
        for (int i = 0; i < threadCount_; ++i) {
            HANDLE dummy = CreateFileW(pipeName_.c_str(),
                                       dummyClientAccess_,
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
        for (HANDLE thread: threads_) {
            if (thread != INVALID_HANDLE_VALUE && thread != nullptr) {
                valid.push_back(thread);
            }
        }

        if (!valid.empty()) {
            WaitForMultipleObjects(static_cast<DWORD>(valid.size()), valid.data(), TRUE, 3000);
        }

        for (HANDLE &thread: threads_) {
            if (thread != INVALID_HANDLE_VALUE && thread != nullptr) {
                CloseHandle(thread);
            }
            thread = INVALID_HANDLE_VALUE;
        }
    }

// Windows CreateThread 要求的标准静态回调函数
    DWORD WINAPI NamedPipeServerPool::ThreadProc(LPVOID param) {
        auto *self = static_cast<NamedPipeServerPool *>(param);
        if (self == nullptr) {
            return 0;
        }

        try {
            self->ServerLoop();
        } catch (...) {
            return -1;
        }

        return 0;
    }

// 功能：循环创建管道实例、等待连接、移交处理、断开连接
    void NamedPipeServerPool::ServerLoop() {
        SECURITY_ATTRIBUTES sa = {};
        PACL acl = nullptr;
        const bool haveSa = MakeAuthenticatedUsersSecurity(&sa, &acl);  // 安全加固

        while (running_.load()) {
            HANDLE pipe = CreateNamedPipeW(pipeName_.c_str(),
                                           openMode_,
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

            try {
                handler_.HandleClient(pipe);
            } catch (...) {
            }
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
        }

        if (haveSa) {
            FreePipeSecurity(&sa, acl);
        }
    }

} // namespace amsi_ipc
