#include "gtest/gtest.h"
#include "AmsiDetectPolicy.h"

using namespace Engine;

class AmsiDetectPolicyTest : public ::testing::Test {};

TEST_F(AmsiDetectPolicyTest, Parse_ValidPolicyWithAutoBlock) {
    AmsiDetectPolicy policy("amsi_detect_feature");
    std::string content = R"({"content":{"auto_block":true,"trust_process":["c:\\windows\\cmd.exe","c:\\test\\app.exe"]}})";
    EXPECT_TRUE(policy.Parse(content));
}

TEST_F(AmsiDetectPolicyTest, Parse_ValidPolicyWithoutAutoBlock) {
    AmsiDetectPolicy policy("amsi_detect_feature");
    std::string content = R"({"content":{"auto_block":false,"trust_process":[]}})";
    EXPECT_TRUE(policy.Parse(content));
}

TEST_F(AmsiDetectPolicyTest, Parse_InvalidJson_ReturnsFalse) {
    AmsiDetectPolicy policy("amsi_detect_feature");
    EXPECT_FALSE(policy.Parse("not json"));
}

TEST_F(AmsiDetectPolicyTest, Parse_EmptyString_ReturnsFalse) {
    AmsiDetectPolicy policy("amsi_detect_feature");
    EXPECT_FALSE(policy.Parse(""));
}

TEST_F(AmsiDetectPolicyTest, Parse_MissingContent_ReturnsFalse) {
    AmsiDetectPolicy policy("amsi_detect_feature");
    std::string content = R"({"no_content":{}})";
    EXPECT_FALSE(policy.Parse(content));
}

TEST_F(AmsiDetectPolicyTest, Parse_MissingTrustProcess_ReturnsFalse) {
    AmsiDetectPolicy policy("amsi_detect_feature");
    std::string content = R"({"content":{"auto_block":true}})";
    EXPECT_FALSE(policy.Parse(content));
}

class AmsiDetectTaskPolicyTest : public ::testing::Test {};

TEST_F(AmsiDetectTaskPolicyTest, Parse_AutoBlockTrue) {
    AmsiDetectTaskPolicy taskPolicy("amsi_detect_task");
    std::string content = R"({"auto_block":true,"trust_process":[]})";
    ASSERT_TRUE(taskPolicy.Parse(content));
    EXPECT_TRUE(taskPolicy.IsAutoBlock());
}

TEST_F(AmsiDetectTaskPolicyTest, Parse_AutoBlockFalse) {
    AmsiDetectTaskPolicy taskPolicy("amsi_detect_task");
    std::string content = R"({"auto_block":false,"trust_process":[]})";
    ASSERT_TRUE(taskPolicy.Parse(content));
    EXPECT_FALSE(taskPolicy.IsAutoBlock());
}

TEST_F(AmsiDetectTaskPolicyTest, Parse_TrustProcessList) {
    AmsiDetectTaskPolicy taskPolicy("amsi_detect_task");
    std::string content = R"({"auto_block":true,"trust_process":["C:\\Windows\\cmd.exe","C:\\Test\\App.exe"]})";
    ASSERT_TRUE(taskPolicy.Parse(content));
    const auto &trust = taskPolicy.GetTrustProcess();
    EXPECT_EQ(trust.size(), 2u);
}

TEST_F(AmsiDetectTaskPolicyTest, Parse_MissingAutoBlock_DefaultsFalse) {
    AmsiDetectTaskPolicy taskPolicy("amsi_detect_task");
    std::string content = R"({"trust_process":[]})";
    ASSERT_TRUE(taskPolicy.Parse(content));
    EXPECT_FALSE(taskPolicy.IsAutoBlock());
}

TEST_F(AmsiDetectTaskPolicyTest, Parse_TrustProcessIsLowercased) {
    AmsiDetectTaskPolicy taskPolicy("amsi_detect_task");
    std::string content = R"({"auto_block":true,"trust_process":["C:\\Windows\\CMD.EXE"]})";
    ASSERT_TRUE(taskPolicy.Parse(content));
    const auto &trust = taskPolicy.GetTrustProcess();
    EXPECT_NE(trust.find("c:\\windows\\cmd.exe"), trust.end());
}

TEST_F(AmsiDetectTaskPolicyTest, Parse_EmptyTrustProcessEntriesSkipped) {
    AmsiDetectTaskPolicy taskPolicy("amsi_detect_task");
    std::string content = R"({"auto_block":true,"trust_process":["  ","C:\\Valid.exe",""]})";
    ASSERT_TRUE(taskPolicy.Parse(content));
    const auto &trust = taskPolicy.GetTrustProcess();
    EXPECT_EQ(trust.size(), 1u);
}

TEST_F(AmsiDetectTaskPolicyTest, Parse_TrustProcessTrimmedBeforeInsert) {
    AmsiDetectTaskPolicy taskPolicy("amsi_detect_task");
    std::string content = R"({"auto_block":true,"trust_process":["  C:\\Windows\\PowerShell.exe  "]})";
    ASSERT_TRUE(taskPolicy.Parse(content));
    const auto &trust = taskPolicy.GetTrustProcess();
    EXPECT_EQ(trust.size(), 1u);
    EXPECT_NE(trust.find("c:\\windows\\powershell.exe"), trust.end());
}

TEST_F(AmsiDetectTaskPolicyTest, Parse_DuplicateTrustProcessDeduplicated) {
    AmsiDetectTaskPolicy taskPolicy("amsi_detect_task");
    std::string content = R"({"auto_block":true,"trust_process":["C:\\A.exe","c:\\a.exe"," C:\\A.EXE "]})";
    ASSERT_TRUE(taskPolicy.Parse(content));
    const auto &trust = taskPolicy.GetTrustProcess();
    EXPECT_EQ(trust.size(), 1u);
    EXPECT_NE(trust.find("c:\\a.exe"), trust.end());
}

TEST_F(AmsiDetectTaskPolicyTest, Parse_NonStringTrustProcessSkipped) {
    AmsiDetectTaskPolicy taskPolicy("amsi_detect_task");
    std::string content = R"({"auto_block":true,"trust_process":[123,"C:\\Valid.exe"]})";
    ASSERT_TRUE(taskPolicy.Parse(content));
    const auto &trust = taskPolicy.GetTrustProcess();
    EXPECT_EQ(trust.size(), 1u);
}

TEST_F(AmsiDetectTaskPolicyTest, Parse_MissingTrustProcess_ReturnsFalse) {
    AmsiDetectTaskPolicy taskPolicy("amsi_detect_task");
    std::string content = R"({"auto_block":true})";
    EXPECT_FALSE(taskPolicy.Parse(content));
}

TEST_F(AmsiDetectTaskPolicyTest, Parse_TrustProcessNotArray_ReturnsFalse) {
    AmsiDetectTaskPolicy taskPolicy("amsi_detect_task");
    std::string content = R"({"auto_block":true,"trust_process":"C:\\A.exe"})";
    EXPECT_FALSE(taskPolicy.Parse(content));
}

TEST_F(AmsiDetectTaskPolicyTest, Parse_InvalidJson_ReturnsFalse) {
    AmsiDetectTaskPolicy taskPolicy("amsi_detect_task");
    EXPECT_FALSE(taskPolicy.Parse("bad json"));
}
