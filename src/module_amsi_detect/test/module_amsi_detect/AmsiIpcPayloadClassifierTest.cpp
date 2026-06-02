#include "gtest/gtest.h"
#include "AmsiIpcPayloadClassifier.h"

class AmsiIpcPayloadClassifierTest : public ::testing::Test {
protected:
    Engine::AmsiIpcPayloadKind Classify(const std::string &payload) {
        return Engine::ClassifyAmsiEventPayload(payload);
    }
};

TEST_F(AmsiIpcPayloadClassifierTest, DetectionPayload) {
    EXPECT_EQ(Classify(R"({"cat":"Detection","rule":"test_rule"})"), Engine::AmsiIpcPayloadKind::Detection);
}

TEST_F(AmsiIpcPayloadClassifierTest, DrainAckPayload) {
    EXPECT_EQ(Classify(R"({"cat":"drain-ack"})"), Engine::AmsiIpcPayloadKind::DrainAck);
}

TEST_F(AmsiIpcPayloadClassifierTest, DiagPayload) {
    EXPECT_EQ(Classify(R"({"cat":"diag","msg":"error"})"), Engine::AmsiIpcPayloadKind::DllDiagnosticLog);
}

TEST_F(AmsiIpcPayloadClassifierTest, RaspLogPayload) {
    EXPECT_EQ(Classify(R"({"sensor":"RaspLog","msg":"info"})"), Engine::AmsiIpcPayloadKind::DllDiagnosticLog);
}

TEST_F(AmsiIpcPayloadClassifierTest, EmptyCatWithRaspLog) {
    EXPECT_EQ(Classify(R"({"cat":"","sensor":"RaspLog"})"), Engine::AmsiIpcPayloadKind::DllDiagnosticLog);
}

TEST_F(AmsiIpcPayloadClassifierTest, UnknownPayload) {
    EXPECT_EQ(Classify(R"({"cat":"unknown_type"})"), Engine::AmsiIpcPayloadKind::UnknownEvent);
}

TEST_F(AmsiIpcPayloadClassifierTest, EmptyPayload) {
    std::string payload;
    EXPECT_EQ(Classify(payload), Engine::AmsiIpcPayloadKind::UnknownEvent);
}

TEST_F(AmsiIpcPayloadClassifierTest, NoCatField) {
    EXPECT_EQ(Classify(R"({"sensor":"SomeOther","data":"test"})"), Engine::AmsiIpcPayloadKind::UnknownEvent);
}

TEST_F(AmsiIpcPayloadClassifierTest, NestedJsonWithCat) {
    std::string payload = R"({"outer":{"cat":"fake"},"cat":"Detection","rule":"r1"})";
    EXPECT_EQ(Classify(payload), Engine::AmsiIpcPayloadKind::UnknownEvent);
}

TEST_F(AmsiIpcPayloadClassifierTest, MalformedJson_StillExtractsCat) {
    EXPECT_EQ(Classify(R"({"cat":"diag" broken json)"), Engine::AmsiIpcPayloadKind::DllDiagnosticLog);
}

TEST_F(AmsiIpcPayloadClassifierTest, DiagWithEscapeSequences) {
    EXPECT_EQ(Classify("{\"cat\":\"diag\",\"msg\":\"line1\\nline2\"}"),
              Engine::AmsiIpcPayloadKind::DllDiagnosticLog);
}

TEST_F(AmsiIpcPayloadClassifierTest, CatValueWithUnicodeEscape_ReturnsUnknown) {
    EXPECT_EQ(Classify(R"({"cat":"di\u0061g","sensor":"Other"})"), Engine::AmsiIpcPayloadKind::UnknownEvent);
}

TEST_F(AmsiIpcPayloadClassifierTest, CatValueIsNotString_ReturnsUnknown) {
    EXPECT_EQ(Classify(R"({"cat":123,"sensor":"Other"})"), Engine::AmsiIpcPayloadKind::UnknownEvent);
}

TEST_F(AmsiIpcPayloadClassifierTest, LowercaseDetectionIsUnknown) {
    EXPECT_EQ(Classify(R"({"cat":"detection","rule":"r1"})"), Engine::AmsiIpcPayloadKind::UnknownEvent);
}

TEST_F(AmsiIpcPayloadClassifierTest, RaspLogIsCaseSensitive) {
    EXPECT_EQ(Classify(R"({"sensor":"rasplog","msg":"info"})"), Engine::AmsiIpcPayloadKind::UnknownEvent);
}

TEST_F(AmsiIpcPayloadClassifierTest, SensorValueWithUnicodeEscape_ReturnsUnknown) {
    EXPECT_EQ(Classify("{\"sensor\":\"Rasp\\u004cog\",\"cat\":\"\"}"), Engine::AmsiIpcPayloadKind::UnknownEvent);
}
