#include "gtest/gtest.h"
#include "AmsiEventProcessor.h"

using namespace Engine;

class AmsiEventProcessorTest : public ::testing::Test {};

TEST_F(AmsiEventProcessorTest, ProcessDetectionEvent_EmptyInput_ReturnsFalse) {
    std::string error;
    EXPECT_FALSE(AmsiEventProcessor::ProcessDetectionEvent("", error));
    EXPECT_FALSE(error.empty());
}

TEST_F(AmsiEventProcessorTest, ProcessDetectionEvent_InvalidJson_ReturnsFalse) {
    std::string error;
    EXPECT_FALSE(AmsiEventProcessor::ProcessDetectionEvent("not json", error));
    EXPECT_FALSE(error.empty());
}

TEST_F(AmsiEventProcessorTest, ProcessDetectionEvent_ValidDetectionJson_ReturnsTrue) {
    std::string json = R"({
        "act": "block",
        "rule": "test_rule",
        "desc": "suspicious activity",
        "script_content": "Get-Process",
        "processPid": 1234,
        "processPath": "C:\\Windows\\System32\\powershell.exe",
        "parentPid": 100,
        "parentProcessPath": "C:\\Windows\\explorer.exe",
        "severity": 2,
        "confidence": 90
    })";
    std::string error;
    EXPECT_TRUE(AmsiEventProcessor::ProcessDetectionEvent(json, error));
}

TEST_F(AmsiEventProcessorTest, ProcessDetectionEvent_AuditAction_ReturnsTrue) {
    std::string json = R"({"act":"audit","rule":"r1","desc":"d1","processPid":1})";
    std::string error;
    EXPECT_TRUE(AmsiEventProcessor::ProcessDetectionEvent(json, error));
}

TEST_F(AmsiEventProcessorTest, ProcessDetectionEvent_UnknownAction_ReturnsTrue) {
    std::string json = R"({"act":"unknown","rule":"r1","desc":"d1","processPid":1})";
    std::string error;
    EXPECT_TRUE(AmsiEventProcessor::ProcessDetectionEvent(json, error));
}

TEST_F(AmsiEventProcessorTest, ProcessDetectionEvent_MinimalJson_ReturnsTrue) {
    std::string json = R"({})";
    std::string error;
    EXPECT_TRUE(AmsiEventProcessor::ProcessDetectionEvent(json, error));
}

TEST_F(AmsiEventProcessorTest, ProcessDetectionEvent_UintSeverityWithinIntRange_ReturnsTrue) {
    std::string json = R"({
        "act":"block",
        "rule":"r1",
        "desc":"d1",
        "severity": 2147483647,
        "confidence": 100,
        "processPid": 123,
        "parentPid": 456
    })";
    std::string error;
    EXPECT_TRUE(AmsiEventProcessor::ProcessDetectionEvent(json, error));
}

TEST_F(AmsiEventProcessorTest, ProcessDetectionEvent_UintSeverityOverIntRange_ReturnsTrue) {
    std::string json = R"({
        "act":"block",
        "rule":"r1",
        "desc":"d1",
        "severity": 4294967295,
        "confidence": 4294967295,
        "processPid": 4294967295,
        "parentPid": 4294967295
    })";
    std::string error;
    EXPECT_TRUE(AmsiEventProcessor::ProcessDetectionEvent(json, error));
}

TEST_F(AmsiEventProcessorTest, ProcessDetectionEvent_StringNumericFieldsUseDefaults_ReturnsTrue) {
    std::string json = R"({
        "act":"audit",
        "severity": "2",
        "confidence": "90",
        "processPid": "1234",
        "parentPid": "5678",
        "script_content": "Write-Host test"
    })";
    std::string error;
    EXPECT_TRUE(AmsiEventProcessor::ProcessDetectionEvent(json, error));
}

TEST_F(AmsiEventProcessorTest, ProcessDetectionEvent_NonStringTextFieldsAreIgnored_ReturnsTrue) {
    std::string json = R"({
        "act": 1,
        "rule": 2,
        "desc": 3,
        "script_content": 4,
        "processPath": 5,
        "parentProcessPath": 6
    })";
    std::string error;
    EXPECT_TRUE(AmsiEventProcessor::ProcessDetectionEvent(json, error));
}

TEST_F(AmsiEventProcessorTest, ProcessDetectionEvent_ChineseProcessPathAndScriptContent_ReturnsTrue) {
    std::string json = R"({
        "act":"block",
        "rule":"r-cn",
        "desc":"包含中文路径",
        "script_content":"Write-Host 中文",
        "processPid":1234,
        "processPath":"C:\\测试目录\\powershell.exe",
        "parentPid":5678,
        "parentProcessPath":"C:\\Windows\\explorer.exe"
    })";
    std::string error;
    EXPECT_TRUE(AmsiEventProcessor::ProcessDetectionEvent(json, error));
}
