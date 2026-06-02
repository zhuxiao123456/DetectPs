/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * AmsiConfigBroadcaster 单元测试
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include "gtest/gtest.h"
#include "../../module/module_amsi_detect/amsi_ipc_host/include/AmsiConfigBroadcaster.h"
#include "../../module/module_amsi_detect/amsi_ipc_host/include/AmsiPipeNames.h"
#include "../../module/module_amsi_detect/amsi_ipc_host/include/AmsiControlStatusChannel.h"

#include <string>
#include <cstdint>
#include <thread>
#include <atomic>
#include <vector>

using namespace amsi_ipc;

namespace {

    class NullControlStatusSink : public IAmsiControlStatusSink {
    public:
        void OnControlStatusLine(const AmsiControlStatusLine &status) override {
            received_.push_back(status.payload);
        }

        std::vector<std::string> GetReceived() const { return received_; }

    private:
        std::vector<std::string> received_;
    };

    std::wstring MakeUniquePipeName(const std::string &suffix) {
        std::wstring base = LR"(\\.\pipe\amsi_test_bcast_)";
        base.append(suffix.begin(), suffix.end());
        return base;
    }

    bool ReadOneSignalFromPipe(const std::wstring &pipeName, BYTE &signal, DWORD timeoutMs = 3000) {
        if (!WaitNamedPipeW(pipeName.c_str(), timeoutMs)) {
            return false;
        }

        HANDLE pipe = CreateFileW(pipeName.c_str(),
                                  GENERIC_READ,
                                  0,
                                  nullptr,
                                  OPEN_EXISTING,
                                  0,
                                  nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            return false;
        }

        DWORD readBytes = 0;
        const BOOL ok = ReadFile(pipe, &signal, 1, &readBytes, nullptr);
        CloseHandle(pipe);
        return ok && readBytes == 1;
    }

}

class AmsiConfigBroadcasterTest : public ::testing::Test {
protected:
    void SetUp() override {
        static int counter = 0;
        pipeName_ = MakeUniquePipeName("config_" + std::to_string(++counter));
    }

    std::wstring pipeName_;
};

TEST_F(AmsiConfigBroadcasterTest, Broadcast_InvalidMaxListeners_ReturnsError) {
    AmsiConfigBroadcaster broadcaster(pipeName_);
    auto result = broadcaster.Broadcast(AmsiControlSignal::Reload, 0, 1000);
    EXPECT_EQ(result.reached, 0);
    EXPECT_EQ(result.lastError, ERROR_INVALID_PARAMETER);
}

TEST_F(AmsiConfigBroadcasterTest, Broadcast_NegativeMaxListeners_ReturnsError) {
    AmsiConfigBroadcaster broadcaster(pipeName_);
    auto result = broadcaster.Broadcast(AmsiControlSignal::Reload, -1, 1000);
    EXPECT_EQ(result.reached, 0);
    EXPECT_EQ(result.lastError, ERROR_INVALID_PARAMETER);
}

TEST_F(AmsiConfigBroadcasterTest, Broadcast_NoListeners_ReturnsZeroReached) {
    AmsiConfigBroadcaster broadcaster(pipeName_);
    auto result = broadcaster.Broadcast(AmsiControlSignal::Reload, 1, 500);
    EXPECT_EQ(result.reached, 0);
}

TEST_F(AmsiConfigBroadcasterTest, Start_ValidPipeName_ReturnsTrue) {
    AmsiConfigBroadcaster broadcaster(pipeName_);
    EXPECT_TRUE(broadcaster.Start());
    broadcaster.Stop();
}

TEST_F(AmsiConfigBroadcasterTest, Start_AlreadyRunning_ReturnsTrue) {
    AmsiConfigBroadcaster broadcaster(pipeName_);
    EXPECT_TRUE(broadcaster.Start());
    EXPECT_TRUE(broadcaster.Start());
    broadcaster.Stop();
}

TEST_F(AmsiConfigBroadcasterTest, Stop_AfterStart_Returns) {
    AmsiConfigBroadcaster broadcaster(pipeName_);
    EXPECT_TRUE(broadcaster.Start());
    broadcaster.Stop();
}

TEST_F(AmsiConfigBroadcasterTest, Stop_WithoutStart_Returns) {
    AmsiConfigBroadcaster broadcaster(pipeName_);
    broadcaster.Stop();
}

TEST_F(AmsiConfigBroadcasterTest, Destructor_WithoutStart_DoesNotCrash) {
    {
        AmsiConfigBroadcaster broadcaster(pipeName_);
    }
}

TEST_F(AmsiConfigBroadcasterTest, Destructor_AfterStart_StopsCleanly) {
    {
        AmsiConfigBroadcaster broadcaster(pipeName_);
        EXPECT_TRUE(broadcaster.Start());
    }
}

TEST_F(AmsiConfigBroadcasterTest, Broadcast_AfterStart_NoListeners_ReturnsZeroReached) {
    AmsiConfigBroadcaster broadcaster(pipeName_);
    EXPECT_TRUE(broadcaster.Start());
    auto result = broadcaster.Broadcast(AmsiControlSignal::Reload, 1, 500);
    EXPECT_EQ(result.reached, 0);
    broadcaster.Stop();
}

TEST_F(AmsiConfigBroadcasterTest, Broadcast_ClientReceivesReloadSignal) {
    AmsiConfigBroadcaster broadcaster(pipeName_);
    ASSERT_TRUE(broadcaster.Start());

    BYTE received = 0;
    std::atomic<bool> readOk{false};
    std::thread client([&]() {
        readOk.store(ReadOneSignalFromPipe(pipeName_, received));
    });

    Sleep(100);
    auto result = broadcaster.Broadcast(AmsiControlSignal::Reload, 1, 1000);
    client.join();
    broadcaster.Stop();

    EXPECT_EQ(result.reached, 1);
    EXPECT_EQ(result.lastError, ERROR_SUCCESS);
    EXPECT_TRUE(readOk.load());
    EXPECT_EQ(received, static_cast<BYTE>(AmsiControlSignal::Reload));
}

TEST_F(AmsiConfigBroadcasterTest, Broadcast_MultipleClientsReceivePauseSignal) {
    AmsiConfigBroadcaster broadcaster(pipeName_, 2);
    ASSERT_TRUE(broadcaster.Start());

    std::vector<BYTE> received(2, 0);
    std::atomic<int> readOkCount{0};
    std::vector<std::thread> clients;
    for (size_t i = 0; i < received.size(); ++i) {
        clients.emplace_back([&, i]() {
            if (ReadOneSignalFromPipe(pipeName_, received[i])) {
                readOkCount.fetch_add(1);
            }
        });
    }

    Sleep(150);
    auto result = broadcaster.Broadcast(AmsiControlSignal::PauseDetection, 2, 1000);
    for (auto &client: clients) {
        client.join();
    }
    broadcaster.Stop();

    EXPECT_EQ(result.reached, 2);
    EXPECT_EQ(result.lastError, ERROR_SUCCESS);
    EXPECT_EQ(readOkCount.load(), 2);
    EXPECT_EQ(received[0], static_cast<BYTE>(AmsiControlSignal::PauseDetection));
    EXPECT_EQ(received[1], static_cast<BYTE>(AmsiControlSignal::PauseDetection));
}

TEST_F(AmsiConfigBroadcasterTest, Start_WithZeroAcceptThreads_ClampsToOneAndBroadcasts) {
    AmsiConfigBroadcaster broadcaster(pipeName_, 0);
    ASSERT_TRUE(broadcaster.Start());

    BYTE received = 0;
    std::atomic<bool> readOk{false};
    std::thread client([&]() {
        readOk.store(ReadOneSignalFromPipe(pipeName_, received));
    });

    Sleep(100);
    auto result = broadcaster.Broadcast(AmsiControlSignal::Unload, 1, 1000);
    client.join();
    broadcaster.Stop();

    EXPECT_EQ(result.reached, 1);
    EXPECT_EQ(result.lastError, ERROR_SUCCESS);
    EXPECT_TRUE(readOk.load());
    EXPECT_EQ(received, static_cast<BYTE>(AmsiControlSignal::Unload));
}

TEST_F(AmsiConfigBroadcasterTest, Stop_WithMultipleAcceptThreads_ReturnsCleanly) {
    AmsiConfigBroadcaster broadcaster(pipeName_, 8);
    ASSERT_TRUE(broadcaster.Start());
    broadcaster.Stop();
}

TEST_F(AmsiConfigBroadcasterTest, Start_WithTooManyAcceptThreads_ClampsAndStopsCleanly) {
    AmsiConfigBroadcaster broadcaster(pipeName_, 64);
    ASSERT_TRUE(broadcaster.Start());
    broadcaster.Stop();
}

TEST_F(AmsiConfigBroadcasterTest, StartStop_WithMultipleAcceptThreadsRepeatedly_ReturnsCleanly) {
    AmsiConfigBroadcaster broadcaster(pipeName_, 8);
    for (int i = 0; i < 3; ++i) {
        ASSERT_TRUE(broadcaster.Start());
        broadcaster.Stop();
    }
}
