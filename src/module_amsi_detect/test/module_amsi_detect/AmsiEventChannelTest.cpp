/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * AmsiEventChannel 单元测试
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include "gtest/gtest.h"
#include "../../module/module_amsi_detect/amsi_ipc_host/include/AmsiEventChannel.h"
#include "../../module/module_amsi_detect/amsi_ipc_host/include/AmsiPipeNames.h"

#include <string>
#include <vector>

using namespace amsi_ipc;

namespace {

    class MockAmsiEventSink : public IAmsiEventSink {
    public:
        void OnEventLine(const AmsiEventLine &event) override {
            events_.push_back(event.payload);
        }

        std::vector<std::string> GetEvents() const {
            return events_;
        }

        size_t EventCount() const {
            return events_.size();
        }

        void Clear() {
            events_.clear();
        }

    private:
        std::vector<std::string> events_;
    };

    std::wstring MakeUniquePipeName(const std::string &suffix) {
        std::wstring base = LR"(\\.\pipe\amsi_test_event_)";
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

    bool ConnectAndClosePipe(const std::wstring &pipeName) {
        HANDLE pipe = CreateFileW(pipeName.c_str(),
                                  GENERIC_WRITE,
                                  0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            return false;
        }
        CloseHandle(pipe);
        return true;
    }

}

class AmsiEventChannelTest : public ::testing::Test {
protected:
    void SetUp() override {
        static int counter = 0;
        pipeName_ = MakeUniquePipeName("event_" + std::to_string(++counter));
    }

    std::wstring pipeName_;
    MockAmsiEventSink sink_;
};

TEST_F(AmsiEventChannelTest, HandleClient_ReadsEventAndForwardsToSink) {
    AmsiEventChannel channel(sink_);
    NamedPipeServerPool pool(pipeName_, 1, channel);

    ASSERT_TRUE(pool.Start());
    Sleep(100);

    std::string testData = R"({"event":"scan_result","content":"clean"})";
    ASSERT_TRUE(WriteToPipe(pipeName_, testData));

    Sleep(500);
    auto events = sink_.GetEvents();
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0], testData);

    pool.Stop();
}

TEST_F(AmsiEventChannelTest, HandleClient_EmptyWrite_NoEventForwarded) {
    AmsiEventChannel channel(sink_);
    NamedPipeServerPool pool(pipeName_, 1, channel);

    ASSERT_TRUE(pool.Start());
    Sleep(100);

    ASSERT_TRUE(ConnectAndClosePipe(pipeName_));

    Sleep(500);
    EXPECT_TRUE(sink_.GetEvents().empty());

    pool.Stop();
}

TEST_F(AmsiEventChannelTest, HandleClient_LargePayload) {
    AmsiEventChannel channel(sink_);
    NamedPipeServerPool pool(pipeName_, 1, channel);

    ASSERT_TRUE(pool.Start());
    Sleep(100);

    std::string largeData(10000, 'A');
    ASSERT_TRUE(WriteToPipe(pipeName_, largeData));

    Sleep(500);
    auto events = sink_.GetEvents();
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0].size(), largeData.size());

    pool.Stop();
}

TEST_F(AmsiEventChannelTest, HandleClient_MultipleClientsSequentially) {
    AmsiEventChannel channel(sink_);
    NamedPipeServerPool pool(pipeName_, 1, channel);

    ASSERT_TRUE(pool.Start());
    Sleep(100);

    for (int i = 0; i < 3; ++i) {
        std::string msg = "event_" + std::to_string(i);
        ASSERT_TRUE(WriteToPipe(pipeName_, msg));
        Sleep(200);
    }

    Sleep(500);
    auto events = sink_.GetEvents();
    ASSERT_GE(events.size(), 3u);

    pool.Stop();
}

TEST_F(AmsiEventChannelTest, HandleClient_BinaryDataWithNulls) {
    AmsiEventChannel channel(sink_);
    NamedPipeServerPool pool(pipeName_, 1, channel);

    ASSERT_TRUE(pool.Start());
    Sleep(100);

    std::string binaryData;
    binaryData.push_back('a');
    binaryData.push_back('b');
    binaryData.push_back('\x00');
    binaryData.push_back('\x01');
    binaryData.push_back('\x02');
    ASSERT_TRUE(WriteToPipe(pipeName_, binaryData));

    Sleep(500);
    auto events = sink_.GetEvents();
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0].size(), binaryData.size());

    pool.Stop();
}
