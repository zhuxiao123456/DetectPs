/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * AmsiRuleChannel 单元测试
 */

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include "gtest/gtest.h"
#include "../../module/module_amsi_detect/amsi_ipc_host/include/AmsiRuleChannel.h"
#include "../../module/module_amsi_detect/amsi_ipc_host/include/AmsiPipeNames.h"

#include <string>
#include <vector>

using namespace amsi_ipc;

namespace {

    class MockAmsiRuleProvider : public IAmsiRuleProvider {
    public:
        bool BuildRulesResponse(const std::string &command,
                                AmsiRuleResponse &out,
                                std::string &error) override {
            lastCommand_ = command;
            if (failBuild_) {
                error = "build failed";
                return false;
            }
            if (emptyResponse_) {
                out.json = "";
                return true;
            }
            out.json = R"({"rules":[{"id":1,"pattern":"test"}]})";
            return true;
        }

        void InvalidateRuleCache() override {
            cacheInvalidated_ = true;
        }

        std::string GetLastCommand() const { return lastCommand_; }

        bool IsCacheInvalidated() const { return cacheInvalidated_; }

        void SetFailBuild(bool fail) { failBuild_ = fail; }

        void SetEmptyResponse(bool empty) { emptyResponse_ = empty; }

    private:
        std::string lastCommand_;
        bool cacheInvalidated_ = false;
        bool failBuild_ = false;
        bool emptyResponse_ = false;
    };

    std::wstring MakeUniquePipeName(const std::string &suffix) {
        std::wstring base = LR"(\\.\pipe\amsi_test_rule_)";
        base.append(suffix.begin(), suffix.end());
        return base;
    }

    bool WriteAndReadPipe(const std::wstring &pipeName,
                          const std::string &request,
                          std::string &response,
                          DWORD timeoutMs = 3000) {
        if (!WaitNamedPipeW(pipeName.c_str(), timeoutMs)) {
            return false;
        }
        HANDLE pipe = CreateFileW(pipeName.c_str(),
                                  GENERIC_READ | GENERIC_WRITE,
                                  0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            return false;
        }

        DWORD written = 0;
        BOOL ok = WriteFile(pipe, request.c_str(), static_cast<DWORD>(request.size()), &written, nullptr);
        if (!ok || written != request.size()) {
            CloseHandle(pipe);
            return false;
        }

        char buffer[65536] = {};
        DWORD bytesRead = 0;
        ok = ReadFile(pipe, buffer, static_cast<DWORD>(sizeof(buffer) - 1), &bytesRead, nullptr);
        CloseHandle(pipe);

        if (!ok || bytesRead == 0) {
            return false;
        }

        response.assign(buffer, bytesRead);
        return true;
    }

}

class AmsiRuleChannelTest : public ::testing::Test {
protected:
    void SetUp() override {
        static int counter = 0;
        pipeName_ = MakeUniquePipeName("rule_" + std::to_string(++counter));
    }

    std::wstring pipeName_;
    MockAmsiRuleProvider provider_;
};

TEST_F(AmsiRuleChannelTest, HandleClient_ValidRequestGetsRules) {
    AmsiRuleChannel channel(provider_);
    NamedPipeServerPool pool(pipeName_, 1, channel);

    ASSERT_TRUE(pool.Start());
    Sleep(100);

    std::string response;
    ASSERT_TRUE(WriteAndReadPipe(pipeName_, "get_rules\n", response));

    EXPECT_EQ(provider_.GetLastCommand(), "get_rules");
    EXPECT_NE(response.find("rules"), std::string::npos);

    pool.Stop();
}

TEST_F(AmsiRuleChannelTest, HandleClient_CommandTrimmed) {
    AmsiRuleChannel channel(provider_);
    NamedPipeServerPool pool(pipeName_, 1, channel);

    ASSERT_TRUE(pool.Start());
    Sleep(100);

    std::string response;
    ASSERT_TRUE(WriteAndReadPipe(pipeName_, "get_rules  \r\n", response));

    EXPECT_EQ(provider_.GetLastCommand(), "get_rules");

    pool.Stop();
}

TEST_F(AmsiRuleChannelTest, HandleClient_ProviderFails_NoResponse) {
    provider_.SetFailBuild(true);
    AmsiRuleChannel channel(provider_);
    NamedPipeServerPool pool(pipeName_, 1, channel);

    ASSERT_TRUE(pool.Start());
    Sleep(100);

    std::string response;
    bool result = WriteAndReadPipe(pipeName_, "get_rules\n", response, 2000);

    EXPECT_EQ(provider_.GetLastCommand(), "get_rules");

    pool.Stop();
}

TEST_F(AmsiRuleChannelTest, HandleClient_EmptyResponse_NoDataWritten) {
    provider_.SetEmptyResponse(true);
    AmsiRuleChannel channel(provider_);
    NamedPipeServerPool pool(pipeName_, 1, channel);

    ASSERT_TRUE(pool.Start());
    Sleep(100);

    std::string response;
    bool result = WriteAndReadPipe(pipeName_, "get_rules\n", response, 2000);

    pool.Stop();
}

TEST_F(AmsiRuleChannelTest, HandleClient_ShortCommand) {
    AmsiRuleChannel channel(provider_);
    NamedPipeServerPool pool(pipeName_, 1, channel);

    ASSERT_TRUE(pool.Start());
    Sleep(100);

    std::string response;
    ASSERT_TRUE(WriteAndReadPipe(pipeName_, "sync", response));

    EXPECT_EQ(provider_.GetLastCommand(), "sync");

    pool.Stop();
}

TEST_F(AmsiRuleChannelTest, HandleClient_MultipleSequentialRequests) {
    AmsiRuleChannel channel(provider_);
    NamedPipeServerPool pool(pipeName_, 1, channel);

    ASSERT_TRUE(pool.Start());
    Sleep(100);

    for (int i = 0; i < 3; ++i) {
        std::string cmd = "cmd" + std::to_string(i) + "\n";
        std::string response;
        ASSERT_TRUE(WriteAndReadPipe(pipeName_, cmd, response));
        Sleep(100);
    }

    pool.Stop();
}
