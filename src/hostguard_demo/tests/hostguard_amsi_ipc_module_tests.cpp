#include "hostguard_amsi_ipc_module.h"
#include "hostguard_file_rule_provider.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <future>
#include <fstream>
#include <stdexcept>
#include <string>
#include <thread>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        return false;
    }
    return true;
}

bool WaitUntil(const std::function<bool()>& predicate, int timeoutMs)
{
    const auto deadline = GetTickCount64() + static_cast<ULONGLONG>(timeoutMs);
    while (GetTickCount64() < deadline) {
        if (predicate()) {
            return true;
        }
        Sleep(5);
    }
    return predicate();
}

std::string TempRoot()
{
    char buffer[MAX_PATH] = {};
    GetTempPathA(static_cast<DWORD>(sizeof(buffer)), buffer);
    std::string root = std::string(buffer) + "hostguard_amsi_module_tests_" + std::to_string(GetCurrentProcessId());
    CreateDirectoryA(root.c_str(), nullptr);
    return root;
}

void WriteRules(const std::string& path, const char* ruleId)
{
    std::ofstream rules(path, std::ios::binary);
    rules << "{\"rules\":[{\"id\":\"" << ruleId << "\",\"sensor\":\"AmsiProvider\"}]}";
}

std::wstring TestPipeName(const wchar_t* suffix)
{
    return std::wstring(LR"(\\.\pipe\hostguard_amsi_module_tests_)") +
           std::to_wstring(GetCurrentProcessId()) + L"_" + suffix;
}

hostguard_demo::HostGuardAmsiIpcConfig RealIpcConfig(const wchar_t* suffix)
{
    hostguard_demo::HostGuardAmsiIpcConfig config;
    config.enableRealIpc = true;
    config.useProductionPipes = false;
    const std::wstring base = std::wstring(suffix) + L"_";
    config.rulesPipeName = TestPipeName((base + L"rules").c_str());
    config.eventsPipeName = TestPipeName((base + L"events").c_str());
    config.controlStatusPipeName = TestPipeName((base + L"status").c_str());
    config.configPipeName = TestPipeName((base + L"config").c_str());
    return config;
}

class FailingRuleProvider final : public amsi_ipc::IAmsiRuleProvider {
public:
    bool BuildRulesResponse(const std::string&, amsi_ipc::AmsiRuleResponse&, std::string& error) override
    {
        error = "injected rule provider failure";
        return false;
    }

    void InvalidateRuleCache() override
    {
        ++invalidations;
    }

    int invalidations = 0;
};

} // namespace

int main()
{
    using namespace hostguard_demo;

    bool ok = true;
    const std::string root = TempRoot();
    const std::string rulesPath = root + "\\rasp_rules.json";
    WriteRules(rulesPath, "amsi-1");

    HostGuardFileRuleProvider provider(rulesPath);
    std::atomic<int> events{0};
    std::atomic<int> statuses{0};
    std::atomic<int> diags{0};

    HostGuardModuleContext context;
    context.ruleProvider = &provider;
    context.loadPolicy = []() {
        return HostGuardPolicySnapshot{true, "policy-v1"};
    };
    context.eventBus = [&](const HostGuardAmsiEventEnvelope& event) {
        if (event.rawJson.find("event-1") != std::string::npos) {
            ++events;
        }
    };
    context.statusBus = [&](const std::string& status) {
        if (status.find("status-1") != std::string::npos) {
            ++statuses;
        }
    };
    context.diagLogger = [&](const HostGuardAmsiAdapterDiag&) {
        ++diags;
    };

    HostGuardAmsiIpcConfig adapterConfig;
    adapterConfig.enableRealIpc = false;
    adapterConfig.useProductionPipes = false;

    HostGuardAmsiIpcModule module;
    std::string error;
    ok &= Expect(module.Init(adapterConfig, context, error), "module Init succeeds");
    ok &= Expect(module.Start(error), "module Start succeeds");
    ok &= Expect(module.GetStatus().adapter.started, "module status reports adapter started");
    ok &= Expect(module.GetStatus().adapter.detectionEnabled, "module starts with policy enabled");

    ok &= Expect(module.InjectRawEventForTest(R"({"cat":"Detection","id":"event-1"})"),
                 "module mock event injection succeeds");
    ok &= Expect(module.InjectStatusForTest(R"({"id":"status-1"})"),
                 "module mock status injection succeeds");
    ok &= Expect(WaitUntil([&]() { return events.load() == 1 && statuses.load() == 1; }, 1000),
                 "module callbacks deliver to injected event/status buses");

    const auto beforeReload = module.GetStatus().adapter.lastRuleHash;
    WriteRules(rulesPath, "amsi-2");
    ok &= Expect(module.ReloadRules(10, error), "module ReloadRules succeeds in mock IPC mode");
    const auto afterReload = module.GetStatus().adapter.lastRuleHash;
    ok &= Expect(!beforeReload.empty() && !afterReload.empty() && beforeReload != afterReload,
                 "module ReloadRules refreshes adapter rule snapshot");

    ok &= Expect(module.ApplyPolicy(false, "policy-off", 10, error),
                 "module ApplyPolicy(false) succeeds in mock IPC mode");
    ok &= Expect(!module.GetStatus().adapter.detectionEnabled,
                 "module ApplyPolicy(false) records detection disabled");
    ok &= Expect(module.ApplyPolicy(true, "policy-on", 10, error),
                 "module ApplyPolicy(true) succeeds in mock IPC mode");
    ok &= Expect(module.GetStatus().adapter.detectionEnabled,
                 "module ApplyPolicy(true) records detection enabled");

    const auto statusText = module.ExportStatusText();
    ok &= Expect(statusText.find("module.started: yes") != std::string::npos,
                 "module status export includes module started state");
    ok &= Expect(statusText.find("adapter.lastRuleHash: ") != std::string::npos,
                 "module status export includes adapter rule hash");

    auto commandResult = module.RunControlCommand("status", 10);
    ok &= Expect(commandResult.ok && commandResult.output.find("module.policyVersion: policy-on") != std::string::npos,
                 "module status control command returns exported status");
    commandResult = module.RunControlCommand("pause-detection", 10);
    ok &= Expect(commandResult.ok && !module.GetStatus().adapter.detectionEnabled,
                 "module pause-detection control command updates policy");
    commandResult = module.RunControlCommand("resume-detection", 10);
    ok &= Expect(commandResult.ok && module.GetStatus().adapter.detectionEnabled,
                 "module resume-detection control command updates policy");
    commandResult = module.RunControlCommand("reload-rules", 10);
    ok &= Expect(commandResult.ok && commandResult.output.find("module.lastReload.command: reload") != std::string::npos,
                 "module reload-rules control command refreshes rules and reports broadcast");
    commandResult = module.RunControlCommand("dump-diag", 10);
    ok &= Expect(commandResult.ok && !commandResult.output.empty(),
                 "module dump-diag control command returns diagnostic text");
    commandResult = module.RunControlCommand("unknown-command", 10);
    ok &= Expect(!commandResult.ok &&
                 commandResult.error.find("unsupported module control command") != std::string::npos,
                 "module rejects unsupported control command");

    module.Stop();
    ok &= Expect(!module.GetStatus().adapter.started, "module Stop stops adapter");
    ok &= Expect(!module.InjectRawEventForTest(R"({"cat":"Detection","id":"after-stop"})"),
                 "module rejects mock event injection after Stop");
    Sleep(50);
    ok &= Expect(events.load() == 1, "Stop prevents callbacks after module resources are stopped");

    module.Stop();
    ok &= Expect(!module.GetStatus().adapter.started, "module Stop is idempotent");

    module.UnInit();
    module.UnInit();
    ok &= Expect(!module.GetStatus().initialized, "module UnInit is idempotent");

    FailingRuleProvider failingProvider;
    HostGuardModuleContext failingContext = context;
    failingContext.ruleProvider = &failingProvider;
    HostGuardAmsiIpcModule failingRulesModule;
    ok &= Expect(failingRulesModule.Init(adapterConfig, failingContext, error),
                 "module Init succeeds with injectable rule provider interface");
    ok &= Expect(!failingRulesModule.Start(error) &&
                 error.find("injected rule provider failure") != std::string::npos,
                 "module Start reports ruleProvider failure");
    ok &= Expect(failingRulesModule.GetStatus().lastError.find("injected rule provider failure") != std::string::npos,
                 "module status records ruleProvider failure");

    HostGuardModuleContext badPolicyContext = context;
    badPolicyContext.loadPolicy = []() -> HostGuardPolicySnapshot {
        throw std::runtime_error("policy unavailable");
    };
    HostGuardAmsiIpcModule badPolicyModule;
    ok &= Expect(badPolicyModule.Init(adapterConfig, badPolicyContext, error),
                 "module Init succeeds before policy load failure");
    ok &= Expect(!badPolicyModule.Start(error) &&
                 error.find("loadPolicy failed: policy unavailable") != std::string::npos,
                 "module Start reports loadPolicy failure");

    HostGuardAmsiIpcModule reloadFailureModule;
    HostGuardAmsiIpcConfig realNotStartedConfig = RealIpcConfig(L"not_started");
    ok &= Expect(reloadFailureModule.Init(realNotStartedConfig, context, error),
                 "real IPC module Init succeeds without Start");
    ok &= Expect(!reloadFailureModule.ReloadRules(10, error),
                 "module ReloadRules fails when real IPC runtime is not started");

    HostGuardAmsiIpcModule pauseFailureModule;
    ok &= Expect(pauseFailureModule.Init(realNotStartedConfig, context, error),
                 "real IPC module Init succeeds for pause failure test");
    ok &= Expect(!pauseFailureModule.ApplyPolicy(false, "policy-off-real-fail", 10, error),
                 "module ApplyPolicy(false) reports pause broadcast failure when runtime is not started");
    ok &= Expect(!pauseFailureModule.GetStatus().adapter.detectionEnabled &&
                 !pauseFailureModule.GetStatus().policyEnabled,
                 "module preserves detection disabled after failed pause broadcast");

    HostGuardAmsiIpcModule startFailureModule;
    HostGuardModuleContext startFailureContext = context;
    startFailureContext.beforeAdapterStartForTest = [](std::string& injectedError) {
        injectedError = "injected adapter Start failure";
        return false;
    };
    ok &= Expect(startFailureModule.Init(adapterConfig, startFailureContext, error),
                 "module Init succeeds before injected adapter Start failure");
    ok &= Expect(!startFailureModule.Start(error),
                 "module Start reports injected adapter Start failure");
    ok &= Expect(startFailureModule.GetStatus().lastError == error,
                 "module status records adapter Start failure");

    std::atomic<bool> callbackEntered{false};
    std::atomic<bool> releaseCallback{false};
    HostGuardModuleContext blockingContext = context;
    blockingContext.eventBus = [&](const HostGuardAmsiEventEnvelope&) {
        callbackEntered = true;
        while (!releaseCallback.load()) {
            Sleep(5);
        }
    };
    HostGuardAmsiIpcModule blockingModule;
    ok &= Expect(blockingModule.Init(adapterConfig, blockingContext, error),
                 "blocking callback module Init succeeds");
    ok &= Expect(blockingModule.Start(error), "blocking callback module Start succeeds");
    ok &= Expect(blockingModule.InjectRawEventForTest(R"({"cat":"Detection","id":"blocking"})"),
                 "blocking callback event injection succeeds");
    ok &= Expect(WaitUntil([&]() { return callbackEntered.load(); }, 1000),
                 "blocking callback enters before Stop");
    auto stopFuture = std::async(std::launch::async, [&]() {
        blockingModule.Stop();
    });
    Sleep(50);
    ok &= Expect(stopFuture.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready,
                 "module Stop waits for in-flight callback");
    releaseCallback = true;
    ok &= Expect(stopFuture.wait_for(std::chrono::seconds(2)) == std::future_status::ready,
                 "module Stop returns after in-flight callback completes");

    return ok ? 0 : 1;
}
