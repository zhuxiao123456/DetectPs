#include "hostguard_demo_app.h"
#include "hostguard_demo_options.h"
#include "hostguard_pipe_client.h"

#include <sstream>
#include <string>
#include <vector>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition) {
        return false;
    }
    return true;
}

std::vector<const char*> Args(std::initializer_list<const char*> values)
{
    return std::vector<const char*>(values);
}

} // namespace

int main()
{
    bool ok = true;

    {
        std::string error;
        HostGuardDemoOptions options;
        const auto args = Args({"hostguard_demo.exe", ".\\config\\rasp_rules.json", ".\\logs", "--production-pipes"});
        ok &= Expect(ParseHostGuardDemoOptions(static_cast<int>(args.size()), args.data(), options, error),
                     "host demo accepts explicit production mode");
        ok &= Expect(options.pipeMode == HostGuardPipeMode::Production,
                     "production mode is recorded");
        ok &= Expect(options.strictHostGuardMode,
                     "production mode keeps strict HostGuard mode");
        ok &= Expect(options.rulesPipeName == LR"(\\.\pipe\amsi_detect_rules)",
                     "production mode uses formal rules pipe");
        ok &= Expect(options.eventsPipeName == LR"(\\.\pipe\amsi_detect_events)",
                     "production mode uses formal events pipe");
        ok &= Expect(options.controlStatusPipeName == LR"(\\.\pipe\amsi_detect_control_status)",
                     "production mode uses formal control status pipe");
        ok &= Expect(options.configPipeName == LR"(\\.\pipe\amsi_detect_config)",
                     "production mode uses formal config pipe");
        ok &= Expect(options.amsiIpc.useProductionPipes,
                     "production mode sets adapter production pipe flag");
    }

    {
        std::string error;
        HostGuardDemoOptions options;
        const auto args = Args({"hostguard_demo.exe", ".\\config\\rasp_rules.json", ".\\logs", "--demo-pipes"});
        ok &= Expect(ParseHostGuardDemoOptions(static_cast<int>(args.size()), args.data(), options, error),
                     "host demo accepts explicit demo mode");
        ok &= Expect(options.pipeMode == HostGuardPipeMode::Demo,
                     "demo mode is recorded");
        ok &= Expect(options.strictHostGuardMode,
                     "demo mode also keeps strict HostGuard mode");
        ok &= Expect(options.rulesPipeName == LR"(\\.\pipe\amsi_detect_rules_demo)",
                     "demo mode uses demo rules pipe");
        ok &= Expect(!options.amsiIpc.useProductionPipes,
                     "demo mode clears adapter production pipe flag");
        ok &= Expect(!options.amsiIpc.enabled,
                     "demo mode keeps adapter disabled by default");
    }

    {
        std::string error;
        HostGuardDemoOptions options;
        const auto args = Args({"hostguard_demo.exe",
                                ".\\config\\rasp_rules.json",
                                ".\\logs",
                                "--demo-pipes",
                                "--amsi-ipc-enabled",
                                "--amsi-ipc-real-ipc"});
        ok &= Expect(ParseHostGuardDemoOptions(static_cast<int>(args.size()), args.data(), options, error),
                     "host demo accepts AMSI IPC adapter flags");
        ok &= Expect(options.amsiIpc.enabled,
                     "AMSI IPC adapter enabled flag is recorded");
        ok &= Expect(options.amsiIpc.enableRealIpc,
                     "AMSI IPC adapter real IPC flag is recorded");
        ok &= Expect(!options.amsiIpc.useProductionPipes,
                     "AMSI IPC adapter keeps demo pipe flag with demo mode");
    }

    {
        std::string error;
        HostGuardDemoOptions options;
        const auto args = Args({"hostguard_demo.exe", ".\\config\\rasp_rules.json", ".\\logs"});
        ok &= Expect(!ParseHostGuardDemoOptions(static_cast<int>(args.size()), args.data(), options, error),
                     "host demo requires explicit pipe mode");
    }

    {
        std::string error;
        HostGuardDemoOptions options;
        const auto args = Args({"hostguard_demo.exe",
                                ".\\config\\rasp_rules.json",
                                ".\\logs",
                                "--demo-pipes",
                                "--bad-amsi-ipc-flag"});
        ok &= Expect(!ParseHostGuardDemoOptions(static_cast<int>(args.size()), args.data(), options, error),
                     "host demo rejects unknown AMSI IPC adapter flag");
    }

    {
        std::ostringstream status;
        HostGuardDemoOptions options;
        options.pipeMode = HostGuardPipeMode::Production;
        HostGuardDemoApp app(options);
        app.PrintStatus(status);
        const std::string text = status.str();
        ok &= Expect(text.find("strictHostGuardMode: yes") < text.find("started:"),
                     "status prints strict HostGuard mode before started");
        ok &= Expect(text.find("pipeMode: production") < text.find("rulesPipeName:"),
                     "status prints pipe mode before pipe list");
    }

    {
        std::string error;
        HostGuardPipeClientOptions options;
        const auto args = Args({"hostguard_demo_pipe_client.exe", "--production-pipes", "rules", "GET_RULES"});
        ok &= Expect(ParseHostGuardPipeClientOptions(static_cast<int>(args.size()), args.data(), options, error),
                     "pipe client accepts explicit production mode");
        ok &= Expect(options.pipeMode == HostGuardPipeMode::Production,
                     "pipe client records production mode");
        ok &= Expect(options.channel == HostGuardPipeClientChannel::Rules,
                     "pipe client records rules channel");
        ok &= Expect(options.payload == "GET_RULES\n",
                     "rules client appends exactly one newline");
    }

    {
        std::string error;
        HostGuardPipeClientOptions options;
        const auto args = Args({"hostguard_demo_pipe_client.exe", "rules", "GET_RULES"});
        ok &= Expect(!ParseHostGuardPipeClientOptions(static_cast<int>(args.size()), args.data(), options, error),
                     "pipe client requires explicit pipe mode");
    }

    {
        std::string error;
        HostGuardPipeClientOptions options;
        const auto args = Args({"hostguard_demo_pipe_client.exe", "--demo-pipes", "event", "{\"x\":1}"});
        ok &= Expect(ParseHostGuardPipeClientOptions(static_cast<int>(args.size()), args.data(), options, error),
                     "pipe client accepts event payload");
        ok &= Expect(options.payload == "{\"x\":1}",
                     "event payload is not modified");
    }

    return ok ? 0 : 1;
}
