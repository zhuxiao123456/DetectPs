/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * AmsiGlobalConf 单元测试
 */

#include "gtest/gtest.h"

#include "AmsiGlobalConf.h"

using namespace Engine;

class AmsiGlobalConfTest : public ::testing::Test {
protected:
    void SetUp() override {}

    void TearDown() override {}
};

TEST_F(AmsiGlobalConfTest, DefaultBroadcastCount)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetBroadcastCount(), 256u);
}

TEST_F(AmsiGlobalConfTest, DefaultMaxPayloadBytes)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetMaxPayloadBytes(), static_cast<size_t>(64 * 1024 - 1));
}

TEST_F(AmsiGlobalConfTest, DefaultDetectionQueueCapacity)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetDetectionQueueCapacity(), static_cast<size_t>(4096));
}

TEST_F(AmsiGlobalConfTest, DefaultDetectionQueueMaxBytes)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetDetectionQueueMaxBytes(), static_cast<size_t>(64 * 1024 * 1024));
}

TEST_F(AmsiGlobalConfTest, DefaultDetectionEnqueueTimeoutMs)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetDetectionEnqueueTimeoutMs(), 50u);
}

TEST_F(AmsiGlobalConfTest, DefaultDllDiagnosticLogQueueCapacity)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetDllDiagnosticLogQueueCapacity(), static_cast<size_t>(2048));
}

TEST_F(AmsiGlobalConfTest, DefaultDllDiagnosticLogQueueMaxBytes)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetDllDiagnosticLogQueueMaxBytes(), static_cast<size_t>(16 * 1024 * 1024));
}

TEST_F(AmsiGlobalConfTest, DefaultDllDiagnosticLogMaxLineBytes)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetDllDiagnosticLogMaxLineBytes(), static_cast<size_t>(4 * 1024));
}

TEST_F(AmsiGlobalConfTest, DefaultDetectionLogMaxLineBytes)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetDetectionLogMaxLineBytes(), static_cast<size_t>(4 * 1024));
}

TEST_F(AmsiGlobalConfTest, DefaultStatusLogMaxLineBytes)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetStatusLogMaxLineBytes(), static_cast<size_t>(4 * 1024));
}

TEST_F(AmsiGlobalConfTest, DefaultDllDiagnosticDuplicateWindowMs)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetDllDiagnosticDuplicateWindowMs(), static_cast<uint32_t>(60 * 1000));
}

TEST_F(AmsiGlobalConfTest, DefaultStatusQueueCapacity)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetStatusQueueCapacity(), static_cast<size_t>(1024));
}

TEST_F(AmsiGlobalConfTest, DefaultStatusQueueMaxBytes)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetStatusQueueMaxBytes(), static_cast<size_t>(16 * 1024 * 1024));
}

TEST_F(AmsiGlobalConfTest, DefaultStatusEnqueueTimeoutMs)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetStatusEnqueueTimeoutMs(), 50u);
}

TEST_F(AmsiGlobalConfTest, DefaultRulePipeNums)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetRulePipeNums(), 4u);
}

TEST_F(AmsiGlobalConfTest, DefaultConfigPipeAcceptThreads)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetConfigPipeAcceptThreads(), 8u);
}

TEST_F(AmsiGlobalConfTest, DefaultEventPipeThreads)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetEventPipeThreads(), 4u);
}

TEST_F(AmsiGlobalConfTest, DefaultStatusPipeThreads)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetStatusPipeThreads(), 2u);
}

TEST_F(AmsiGlobalConfTest, DefaultDiagDroppedSummaryIntervalMs)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetDiagDroppedSummaryIntervalMs(), static_cast<size_t>(60 * 1000));
}

TEST_F(AmsiGlobalConfTest, ParseAmsiConf_MissingFile_KeepsDefaults)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    conf.ParseAmsiConf();

    EXPECT_EQ(conf.GetBroadcastCount(), 256u);
    EXPECT_EQ(conf.GetRulePipeNums(), 4u);
    EXPECT_EQ(conf.GetConfigPipeAcceptThreads(), 8u);
    EXPECT_EQ(conf.GetEventPipeThreads(), 4u);
    EXPECT_EQ(conf.GetStatusPipeThreads(), 2u);
    EXPECT_EQ(conf.GetMaxPayloadBytes(), static_cast<size_t>(64 * 1024 - 1));
    EXPECT_EQ(conf.GetDetectionQueueCapacity(), static_cast<size_t>(4096));
    EXPECT_EQ(conf.GetDetectionQueueMaxBytes(), static_cast<size_t>(64 * 1024 * 1024));
    EXPECT_EQ(conf.GetDetectionEnqueueTimeoutMs(), 50u);
    EXPECT_EQ(conf.GetDllDiagnosticLogQueueCapacity(), static_cast<size_t>(2048));
    EXPECT_EQ(conf.GetDllDiagnosticLogQueueMaxBytes(), static_cast<size_t>(16 * 1024 * 1024));
    EXPECT_EQ(conf.GetDllDiagnosticLogMaxLineBytes(), static_cast<size_t>(4 * 1024));
    EXPECT_EQ(conf.GetDetectionLogMaxLineBytes(), static_cast<size_t>(4 * 1024));
    EXPECT_EQ(conf.GetStatusLogMaxLineBytes(), static_cast<size_t>(4 * 1024));
    EXPECT_EQ(conf.GetDllDiagnosticDuplicateWindowMs(), static_cast<uint32_t>(60 * 1000));
    EXPECT_EQ(conf.GetStatusQueueCapacity(), static_cast<size_t>(1024));
    EXPECT_EQ(conf.GetStatusQueueMaxBytes(), static_cast<size_t>(16 * 1024 * 1024));
    EXPECT_EQ(conf.GetStatusEnqueueTimeoutMs(), 50u);
    EXPECT_EQ(conf.GetDiagDroppedSummaryIntervalMs(), static_cast<size_t>(60 * 1000));
}

TEST_F(AmsiGlobalConfTest, GetInstance_ReturnsSameInstance)
{
    auto& inst1 = AmsiGlobalConf::GetInstance();
    auto& inst2 = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(&inst1, &inst2);
}

TEST_F(AmsiGlobalConfTest, UnloadBroadcastCycles)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetUnloadBroadcastCycles(), 3u);
}

TEST_F(AmsiGlobalConfTest, UnloadBroadcastTimeoutMs)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetUnloadBroadcastTimeoutMs(), 1000u);
}

TEST_F(AmsiGlobalConfTest, UnloadSettleMs)
{
    auto& conf = AmsiGlobalConf::GetInstance();
    EXPECT_EQ(conf.GetUnloadSettleMs(), 3000u);
}
