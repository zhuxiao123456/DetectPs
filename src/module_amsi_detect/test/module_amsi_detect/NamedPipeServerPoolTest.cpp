/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * NamedPipeServerPool 单元测试
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include "gtest/gtest.h"
#include "../../module/module_amsi_detect/amsi_ipc_host/include/NamedPipeServerPool.h"

#include <string>
#include <vector>
#include <atomic>

using namespace amsi_ipc;

namespace {

    class CountingHandler : public INamedPipeClientHandler {
    public:
        void HandleClient(HANDLE pipe) override {
            char buffer[256] = {};
            DWORD bytesRead = 0;
            if (ReadFile(pipe, buffer, static_cast<DWORD>(sizeof(buffer) - 1), &bytesRead, nullptr)) {
                if (bytesRead > 0) {
                    count_.fetch_add(1);
                }
            }
        }

        int GetCount() const { return count_.load(); }

    private:
        std::atomic<int> count_{0};
    };

    std::wstring MakeUniquePipeName(const std::string &suffix) {
        std::wstring base = LR"(\\.\pipe\amsi_test_pool_)";
        base.append(suffix.begin(), suffix.end());
        return base;
    }

    bool WriteToPipe(const std::wstring &pipeName, const std::string &data) {
        HANDLE pipe = CreateFileW(pipeName.c_str(),
                                  GENERIC_WRITE,
                                  0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            return false;
        }
        DWORD written = 0;
        BOOL ok = WriteFile(pipe, data.c_str(), static_cast<DWORD>(data.size()), &written, nullptr);
        CloseHandle(pipe);
        return ok && written == data.size();
    }

}

class NamedPipeServerPoolTest : public ::testing::Test {
protected:
    void SetUp() override {
        static int counter = 0;
        pipeName_ = MakeUniquePipeName("pool_" + std::to_string(++counter));
    }

    std::wstring pipeName_;
    CountingHandler handler_;
};

TEST_F(NamedPipeServerPoolTest, StartWithValidConfig_ReturnsTrue) {
    NamedPipeServerPool pool(pipeName_, 1, handler_);
    EXPECT_TRUE(pool.Start());
    pool.Stop();
}

TEST_F(NamedPipeServerPoolTest, StartWithZeroThreads_ReturnsFalse) {
    NamedPipeServerPool pool(pipeName_, 0, handler_);
    EXPECT_FALSE(pool.Start());
}

TEST_F(NamedPipeServerPoolTest, StartIsIdempotent) {
    NamedPipeServerPool pool(pipeName_, 1, handler_);
    EXPECT_TRUE(pool.Start());
    EXPECT_TRUE(pool.Start());
    pool.Stop();
}

TEST_F(NamedPipeServerPoolTest, StopWithoutStart_DoesNotCrash) {
    NamedPipeServerPool pool(pipeName_, 1, handler_);
    pool.Stop();
}

TEST_F(NamedPipeServerPoolTest, StopIsIdempotent) {
    NamedPipeServerPool pool(pipeName_, 1, handler_);
    ASSERT_TRUE(pool.Start());
    pool.Stop();
    pool.Stop();
}

TEST_F(NamedPipeServerPoolTest, DestructorCallsStop) {
    {
        NamedPipeServerPool pool(pipeName_, 1, handler_);
        ASSERT_TRUE(pool.Start());
        Sleep(50);
    }
}

TEST_F(NamedPipeServerPoolTest, HandleClient_ProcessesData) {
    NamedPipeServerPool pool(pipeName_, 1, handler_);
    ASSERT_TRUE(pool.Start());
    Sleep(100);

    ASSERT_TRUE(WriteToPipe(pipeName_, "test_data"));
    Sleep(500);

    EXPECT_EQ(handler_.GetCount(), 1);

    pool.Stop();
}

TEST_F(NamedPipeServerPoolTest, MultipleThreadsConcurrentClients) {
    const int threadCount = 3;
    NamedPipeServerPool pool(pipeName_, threadCount, handler_);
    ASSERT_TRUE(pool.Start());
    Sleep(100);

    for (int i = 0; i < threadCount; ++i) {
        std::string msg = "msg_" + std::to_string(i);
        ASSERT_TRUE(WriteToPipe(pipeName_, msg));
        Sleep(200);
    }

    Sleep(500);
    EXPECT_EQ(handler_.GetCount(), threadCount);

    pool.Stop();
}

TEST_F(NamedPipeServerPoolTest, RestartAfterStop) {
    NamedPipeServerPool pool(pipeName_, 1, handler_);
    ASSERT_TRUE(pool.Start());
    Sleep(50);
    pool.Stop();
    Sleep(100);

    ASSERT_TRUE(pool.Start());
    Sleep(100);

    ASSERT_TRUE(WriteToPipe(pipeName_, "after_restart"));
    Sleep(500);

    EXPECT_GE(handler_.GetCount(), 1);

    pool.Stop();
}

TEST_F(NamedPipeServerPoolTest, StopWakesUpBlockedThreads) {
    NamedPipeServerPool pool(pipeName_, 2, handler_);
    ASSERT_TRUE(pool.Start());
    Sleep(100);

    pool.Stop();

    SUCCEED();
}
