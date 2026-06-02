/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * AmsiControlStatusChannel 单元测试
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include "gtest/gtest.h"
#include "../../module/module_amsi_detect/amsi_ipc_host/include/AmsiControlStatusChannel.h"
#include "../../module/module_amsi_detect/amsi_ipc_host/include/AmsiPipeNames.h"

#include <string>
#include <vector>

using namespace amsi_ipc;

namespace {

    class MockAmsiControlStatusSink : public IAmsiControlStatusSink {
    public:
        void OnControlStatusLine(const AmsiControlStatusLine &status) override {
            statuses_.push_back(status.payload);
        }

        std::vector<std::string> GetStatuses() const {
            return statuses_;
        }

        size_t StatusCount() const {
            return statuses_.size();
        }

        void Clear() {
            statuses_.clear();
        }

    private:
        std::vector<std::string> statuses_;
    };

    std::wstring MakeUniquePipeName(const std::string &suffix) {
        std::wstring base = LR"(\\.\pipe\amsi_test_ctrl_)";
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

class AmsiControlStatusChannelTest : public ::testing::Test {
protected:
    void SetUp() override {
        static int counter = 0;
        pipeName_ = MakeUniquePipeName("status_" + std::to_string(++counter));
    }

    std::wstring pipeName_;
    MockAmsiControlStatusSink sink_;
};

TEST_F(AmsiControlStatusChannelTest, HandleClient_ReadsStatusAndForwardsToSink) {
    AmsiControlStatusChannel channel(sink_);
    NamedPipeServerPool pool(pipeName_, 1, channel);

    ASSERT_TRUE(pool.Start());
    Sleep(100);

    std::string testData = R"({"status":"loaded","pid":1234})";
    ASSERT_TRUE(WriteToPipe(pipeName_, testData));

    Sleep(500);
    auto statuses = sink_.GetStatuses();
    ASSERT_EQ(statuses.size(), 1u);
    EXPECT_EQ(statuses[0], testData);

    pool.Stop();
}

TEST_F(AmsiControlStatusChannelTest, HandleClient_EmptyWrite_NoStatusForwarded) {
    AmsiControlStatusChannel channel(sink_);
    NamedPipeServerPool pool(pipeName_, 1, channel);

    ASSERT_TRUE(pool.Start());
    Sleep(100);

    HANDLE pipe = CreateFileW(pipeName_.c_str(),
                              GENERIC_WRITE,
                              0, nullptr, OPEN_EXISTING, 0, nullptr);
    ASSERT_NE(pipe, INVALID_HANDLE_VALUE);
    CloseHandle(pipe);

    Sleep(500);
    EXPECT_TRUE(sink_.GetStatuses().empty());

    pool.Stop();
}

TEST_F(AmsiControlStatusChannelTest, HandleClient_MultipleStatusReports) {
    AmsiControlStatusChannel channel(sink_);
    NamedPipeServerPool pool(pipeName_, 1, channel);

    ASSERT_TRUE(pool.Start());
    Sleep(100);

    for (int i = 0; i < 3; ++i) {
        std::string msg = R"({"status":"heartbeat","seq":)" + std::to_string(i) + "}";
        ASSERT_TRUE(WriteToPipe(pipeName_, msg));
        Sleep(200);
    }

    Sleep(500);
    auto statuses = sink_.GetStatuses();
    ASSERT_GE(statuses.size(), 3u);

    pool.Stop();
}

TEST_F(AmsiControlStatusChannelTest, HandleClient_LongPayload) {
    AmsiControlStatusChannel channel(sink_);
    NamedPipeServerPool pool(pipeName_, 1, channel);

    ASSERT_TRUE(pool.Start());
    Sleep(100);

    std::string longData(5000, 'X');
    ASSERT_TRUE(WriteToPipe(pipeName_, longData));

    Sleep(500);
    auto statuses = sink_.GetStatuses();
    ASSERT_EQ(statuses.size(), 1u);
    EXPECT_EQ(statuses[0].size(), longData.size());

    pool.Stop();
}
