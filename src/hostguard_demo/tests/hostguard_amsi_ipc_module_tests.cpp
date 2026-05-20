#include "hostguard_amsi_ipc_module.h"
#include "hostguard_file_rule_provider.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <cstdio>
#include <fstream>
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

    module.Stop();
    ok &= Expect(!module.GetStatus().adapter.started, "module Stop stops adapter");
    ok &= Expect(!module.InjectRawEventForTest(R"({"cat":"Detection","id":"after-stop"})"),
                 "module rejects mock event injection after Stop");
    Sleep(50);
    ok &= Expect(events.load() == 1, "Stop prevents callbacks after module resources are stopped");

    module.Stop();
    ok &= Expect(!module.GetStatus().adapter.started, "module Stop is idempotent");

    return ok ? 0 : 1;
}
