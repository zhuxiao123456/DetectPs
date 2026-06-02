#include "gtest/gtest.h"
#include "AmsiIpcRuntime.h"

using namespace Engine;

class AmsiIpcRuntimeTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}

    AmsiIpcRuntimeConfig MakeValidConfig() {
        AmsiIpcRuntimeConfig config;
        config.amsiIpcEnabled = true;
        config.enableRealIpc = true;
        config.useProductionPipes = true;
        config.dllPath = "C:\\test\\amsi.dll";
        config.rulePath = "C:\\test\\rules";
        config.versionPath = "C:\\test\\version";
        config.version = "1.0.0";
        return config;
    }

    AmsiDetect::AmsiRuleSnapshot MakeValidSnapshot() {
        AmsiDetect::AmsiRuleSnapshot snapshot;
        snapshot.amsiRulesJson = R"({"rules":[{"id":1}]})";
        snapshot.version = "1.0.0";
        return snapshot;
    }
};

TEST_F(AmsiIpcRuntimeTest, Init_DisabledIpc_ReturnsFalse) {
    AmsiIpcRuntime runtime;
    AmsiIpcRuntimeConfig config;
    config.amsiIpcEnabled = false;
    std::string error;
    EXPECT_FALSE(runtime.Init(config, error));
    EXPECT_FALSE(error.empty());
}

TEST_F(AmsiIpcRuntimeTest, Init_DisabledRealIpc_ReturnsFalse) {
    AmsiIpcRuntime runtime;
    AmsiIpcRuntimeConfig config;
    config.amsiIpcEnabled = true;
    config.enableRealIpc = false;
    std::string error;
    EXPECT_FALSE(runtime.Init(config, error));
}

TEST_F(AmsiIpcRuntimeTest, Init_NonProductionPipes_ReturnsFalse) {
    AmsiIpcRuntime runtime;
    AmsiIpcRuntimeConfig config;
    config.amsiIpcEnabled = true;
    config.enableRealIpc = true;
    config.useProductionPipes = false;
    std::string error;
    EXPECT_FALSE(runtime.Init(config, error));
}

TEST_F(AmsiIpcRuntimeTest, Init_ValidConfig_ReturnsTrue) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    EXPECT_TRUE(runtime.Init(config, error));
    EXPECT_TRUE(error.empty());
}

TEST_F(AmsiIpcRuntimeTest, IsRunning_DefaultFalse) {
    AmsiIpcRuntime runtime;
    EXPECT_FALSE(runtime.IsRunning());
}

TEST_F(AmsiIpcRuntimeTest, GetStats_DefaultState) {
    AmsiIpcRuntime runtime;
    auto stats = runtime.GetStats();
    EXPECT_FALSE(stats.initialized);
    EXPECT_FALSE(stats.running);
}

TEST_F(AmsiIpcRuntimeTest, GetStats_AfterInit) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    runtime.Init(config, error);
    auto stats = runtime.GetStats();
    EXPECT_TRUE(stats.initialized);
    EXPECT_FALSE(stats.running);
}

TEST_F(AmsiIpcRuntimeTest, Start_WithoutInit_ReturnsFalse) {
    AmsiIpcRuntime runtime;
    auto snapshot = MakeValidSnapshot();
    std::string error;
    EXPECT_FALSE(runtime.Start(snapshot, error));
}

TEST_F(AmsiIpcRuntimeTest, Stop_WithoutStart_ReturnsTrue) {
    AmsiIpcRuntime runtime;
    std::string error;
    EXPECT_TRUE(runtime.Stop(1000, error));
}

TEST_F(AmsiIpcRuntimeTest, UpdateRules_WithoutInit_ReturnsFalse) {
    AmsiIpcRuntime runtime;
    auto snapshot = MakeValidSnapshot();
    std::string error;
    EXPECT_FALSE(runtime.UpdateRules(snapshot, error));
}

TEST_F(AmsiIpcRuntimeTest, UpdateRules_AfterInit_ReturnsTrue) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    runtime.Init(config, error);
    auto snapshot = MakeValidSnapshot();
    EXPECT_TRUE(runtime.UpdateRules(snapshot, error));
}

TEST_F(AmsiIpcRuntimeTest, UpdateRules_EmptyRulesJson_ReturnsTrue) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    runtime.Init(config, error);
    AmsiDetect::AmsiRuleSnapshot snapshot;
    snapshot.amsiRulesJson = "";
    snapshot.version = "1.0.0";
    EXPECT_TRUE(runtime.UpdateRules(snapshot, error));
}

TEST_F(AmsiIpcRuntimeTest, UpdateRules_EmptyVersion_ReturnsTrue) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    runtime.Init(config, error);
    AmsiDetect::AmsiRuleSnapshot snapshot;
    snapshot.amsiRulesJson = R"({"rules":[]})";
    snapshot.version = "";
    EXPECT_TRUE(runtime.UpdateRules(snapshot, error));
}

TEST_F(AmsiIpcRuntimeTest, EnterUpgradeUnloadingState_WithoutInit_ReturnsFalse) {
    AmsiIpcRuntime runtime;
    std::string error;
    EXPECT_FALSE(runtime.EnterUpgradeUnloadingState("upgrade-test", error));
}

TEST_F(AmsiIpcRuntimeTest, EnterUpgradeUnloadingState_AfterInit_ReturnsFalse) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    runtime.Init(config, error);
    auto snapshot = MakeValidSnapshot();
    runtime.UpdateRules(snapshot, error);
    EXPECT_FALSE(runtime.EnterUpgradeUnloadingState("upgrade-test", error));
}

TEST_F(AmsiIpcRuntimeTest, RestorePreUpgradeSnapshot_WithoutInit_ReturnsFalse) {
    AmsiIpcRuntime runtime;
    std::string error;
    EXPECT_FALSE(runtime.RestorePreUpgradeSnapshot(error));
}

TEST_F(AmsiIpcRuntimeTest, RestorePreUpgradeSnapshot_AfterInit_NoSnapshot_ReturnsTrue) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    runtime.Init(config, error);
    EXPECT_TRUE(runtime.RestorePreUpgradeSnapshot(error));
}

TEST_F(AmsiIpcRuntimeTest, RestorePreUpgradeSnapshot_AfterEnterUpgrade_ReturnsTrue) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    runtime.Init(config, error);
    auto snapshot = MakeValidSnapshot();
    runtime.UpdateRules(snapshot, error);
    runtime.EnterUpgradeUnloadingState("upgrade-test", error);
    EXPECT_TRUE(runtime.RestorePreUpgradeSnapshot(error));
}

TEST_F(AmsiIpcRuntimeTest, PauseDetection_WithoutRunning_ReturnsTrue) {
    AmsiIpcRuntime runtime;
    std::string error;
    EXPECT_TRUE(runtime.PauseDetection(1000, error));
}

TEST_F(AmsiIpcRuntimeTest, ResumeDetection_WithoutRunning_ReturnsTrue) {
    AmsiIpcRuntime runtime;
    std::string error;
    EXPECT_TRUE(runtime.ResumeDetection(1000, error));
}

TEST_F(AmsiIpcRuntimeTest, Unload_WithoutRunning_ReturnsTrue) {
    AmsiIpcRuntime runtime;
    std::string error;
    EXPECT_TRUE(runtime.Unload(1000, error));
}

TEST_F(AmsiIpcRuntimeTest, Reload_WithoutRunning_ReturnsFalse) {
    AmsiIpcRuntime runtime;
    std::string error;
    EXPECT_FALSE(runtime.Reload(1000, error));
}

TEST_F(AmsiIpcRuntimeTest, GetLastBroadcastSummary_DefaultEmpty) {
    AmsiIpcRuntime runtime;
    auto summary = runtime.GetLastBroadcastSummary("reload");
    EXPECT_EQ(summary.reached, 0u);
    EXPECT_EQ(summary.lastError, 0u);
}

TEST_F(AmsiIpcRuntimeTest, GetLastBroadcastSummary_UnknownCommand) {
    AmsiIpcRuntime runtime;
    auto summary = runtime.GetLastBroadcastSummary("unknown");
    EXPECT_EQ(summary.reached, 0u);
}

TEST_F(AmsiIpcRuntimeTest, Destructor_WithoutInit_DoesNotCrash) {
    {
        AmsiIpcRuntime runtime;
    }
}

TEST_F(AmsiIpcRuntimeTest, GetStats_AfterMultipleInitCalls) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    runtime.Init(config, error);
    runtime.Init(config, error);
    auto stats = runtime.GetStats();
    EXPECT_TRUE(stats.initialized);
}

TEST_F(AmsiIpcRuntimeTest, Start_AfterInitWithEmptySnapshot_ReturnsTrue) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    runtime.Init(config, error);
    AmsiDetect::AmsiRuleSnapshot snapshot;
    snapshot.amsiRulesJson = R"({"rules":[]})";
    snapshot.version = "1.0.0";
    EXPECT_TRUE(runtime.Start(snapshot, error));
    EXPECT_TRUE(runtime.IsRunning());
    runtime.Stop(1000, error);
}

TEST_F(AmsiIpcRuntimeTest, Stop_AfterStart_ReturnsTrue) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    runtime.Init(config, error);
    auto snapshot = MakeValidSnapshot();
    EXPECT_TRUE(runtime.Start(snapshot, error));
    EXPECT_TRUE(runtime.IsRunning());
    EXPECT_TRUE(runtime.Stop(1000, error));
    EXPECT_FALSE(runtime.IsRunning());
}

TEST_F(AmsiIpcRuntimeTest, IsRunning_AfterStop_ReturnsFalse) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    runtime.Init(config, error);
    auto snapshot = MakeValidSnapshot();
    runtime.Start(snapshot, error);
    runtime.Stop(1000, error);
    EXPECT_FALSE(runtime.IsRunning());
}

TEST_F(AmsiIpcRuntimeTest, GetStats_AfterStart) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    runtime.Init(config, error);
    auto snapshot = MakeValidSnapshot();
    runtime.Start(snapshot, error);
    auto stats = runtime.GetStats();
    EXPECT_TRUE(stats.running);
    runtime.Stop(1000, error);
}

TEST_F(AmsiIpcRuntimeTest, UpdateRules_AfterStart_ReturnsTrue) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    runtime.Init(config, error);
    auto snapshot = MakeValidSnapshot();
    runtime.Start(snapshot, error);
    auto newSnapshot = MakeValidSnapshot();
    EXPECT_TRUE(runtime.UpdateRules(newSnapshot, error));
    runtime.Stop(1000, error);
}

TEST_F(AmsiIpcRuntimeTest, PauseDetection_AfterStart_NoListeners_ReturnsFalse) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    runtime.Init(config, error);
    auto snapshot = MakeValidSnapshot();
    runtime.Start(snapshot, error);
    EXPECT_FALSE(runtime.PauseDetection(1000, error));
    runtime.Stop(1000, error);
}

TEST_F(AmsiIpcRuntimeTest, ResumeDetection_AfterStart_NoListeners_ReturnsFalse) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    runtime.Init(config, error);
    auto snapshot = MakeValidSnapshot();
    runtime.Start(snapshot, error);
    runtime.PauseDetection(1000, error);
    EXPECT_FALSE(runtime.ResumeDetection(1000, error));
    runtime.Stop(1000, error);
}

TEST_F(AmsiIpcRuntimeTest, Unload_AfterStart_NoListeners_ReturnsFalse) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    runtime.Init(config, error);
    auto snapshot = MakeValidSnapshot();
    runtime.Start(snapshot, error);
    EXPECT_FALSE(runtime.Unload(1000, error));
    runtime.Stop(1000, error);
}

TEST_F(AmsiIpcRuntimeTest, Reload_AfterStart_NoListeners_ReturnsFalse) {
    AmsiIpcRuntime runtime;
    auto config = MakeValidConfig();
    std::string error;
    runtime.Init(config, error);
    auto snapshot = MakeValidSnapshot();
    runtime.Start(snapshot, error);
    EXPECT_FALSE(runtime.Reload(1000, error));
    runtime.Stop(1000, error);
}
