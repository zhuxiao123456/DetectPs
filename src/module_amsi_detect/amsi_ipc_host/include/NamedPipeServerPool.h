/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * 多线程命名管道池: 实现了一个经典的“单请求-单线程”响应池模型，专门解决多个目标进程同时连上来请求数据时的并发排队问题
 */
#ifndef NAMED_PIPE_SERVER_POOL_H
#define NAMED_PIPE_SERVER_POOL_H

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <mutex>
#include <string>
#include <vector>

namespace amsi_ipc {
// 定义HandleClient(HANDLE pipe)。这是一个回调契约，管道池不关心具体的业务，它只负责建立连接，连上后就把 pipe 句柄扔给实现了这个接口的籿
    class INamedPipeClientHandler {
    public:
        virtual ~INamedPipeClientHandler() = default;
        virtual void HandleClient(HANDLE pipe) = 0;
    };
// 维护了一个HANDLE 线程数组和一个原子布尔 running_ 来控制生命周期
    class NamedPipeServerPool {
    public:
        // 输入管道名称、线程数量、管道读写缓冲区大小、管道打开模式(默认双向)、用于停止线程时的伪造客户端权限
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

        bool Start();  // 启动 threadCount_ 个线程，每个线程执行 ThreadProc
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
        std::mutex mutex_;
        bool validConfig_ = true;
    };

} // namespace amsi_ipc

#endif
