#include "amsi_rule_channel.h"

#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

class FakeRuleProvider : public amsi_ipc::IAmsiRuleProvider {
public:
    bool BuildRulesResponse(const std::string& command,
                            amsi_ipc::AmsiRuleResponse& out,
                            std::string& error) override
    {
        commands.push_back(command);
        if (command == "GET_ALL_RULES") {
            out.json = allRulesJson.empty() ? R"({"kind":"all"})" : allRulesJson;
            return true;
        }
        if (command == "GET_RULES") {
            out.json = R"({"kind":"amsi"})";
            return true;
        }
        error = "unknown command: " + command;
        return false;
    }

    void InvalidateRuleCache() override {}

    std::vector<std::string> commands;
    std::string allRulesJson;
};

bool Expect(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << "FAIL: " << message << "\n";
        return false;
    }
    return true;
}

std::string ExchangeWithChannel(amsi_ipc::AmsiRuleChannel& channel,
                                const std::string& request)
{
    const wchar_t* pipeName = LR"(\\.\pipe\amsi_rule_channel_unit_test)";
    HANDLE server = CreateNamedPipeW(pipeName,
                                     PIPE_ACCESS_DUPLEX,
                                     PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                     1,
                                     4096,
                                     256,
                                     0,
                                     nullptr);
    if (server == INVALID_HANDLE_VALUE) {
        return "__create_pipe_failed__";
    }

    std::thread serverThread([&]() {
        BOOL connected = ConnectNamedPipe(server, nullptr);
        if (connected || GetLastError() == ERROR_PIPE_CONNECTED) {
            channel.HandleClient(server);
        }
        DisconnectNamedPipe(server);
        CloseHandle(server);
    });

    HANDLE client = CreateFileW(pipeName,
                                GENERIC_READ | GENERIC_WRITE,
                                0,
                                nullptr,
                                OPEN_EXISTING,
                                0,
                                nullptr);
    if (client == INVALID_HANDLE_VALUE) {
        serverThread.join();
        return "__connect_client_failed__";
    }

    DWORD written = 0;
    WriteFile(client, request.data(), static_cast<DWORD>(request.size()), &written, nullptr);

    std::string response;
    char chunk[4096] = {};
    DWORD bytesRead = 0;
    while (ReadFile(client, chunk, static_cast<DWORD>(sizeof(chunk)), &bytesRead, nullptr) && bytesRead > 0) {
        response.append(chunk, bytesRead);
    }

    CloseHandle(client);
    serverThread.join();

    return response;
}

void CaptureChannelLog(const char* message, void* context)
{
    auto* logs = static_cast<std::vector<std::string>*>(context);
    if (logs && message) {
        logs->push_back(message);
    }
}

} // namespace

int main()
{
    bool ok = true;
    FakeRuleProvider provider;
    amsi_ipc::AmsiRuleChannel channel(provider);
    std::vector<std::string> logs;
    channel.SetLogCallback(CaptureChannelLog, &logs);

    ok &= Expect(ExchangeWithChannel(channel, "GET_ALL_RULES\n") == R"({"kind":"all"})" "\n",
                 "GET_ALL_RULES returns assembled response with newline");
    ok &= Expect(ExchangeWithChannel(channel, "GET_RULES\r\n") == R"({"kind":"amsi"})" "\n",
                 "GET_RULES returns AMSI-filtered response with newline");
    ok &= Expect(ExchangeWithChannel(channel, "UNKNOWN\n").empty(),
                  "unknown command writes no payload");
    provider.allRulesJson.assign((2 * 1024 * 1024) - 2, 'A');
    ok &= Expect(ExchangeWithChannel(channel, "GET_ALL_RULES\n").size() == (2 * 1024 * 1024) - 1,
                 "wire payload smaller than 2MB is allowed");
    provider.allRulesJson.assign((2 * 1024 * 1024) - 1, 'B');
    ok &= Expect(ExchangeWithChannel(channel, "GET_ALL_RULES\n").size() == (2 * 1024 * 1024),
                 "wire payload exactly 2MB is allowed");
    provider.allRulesJson.assign(2 * 1024 * 1024, 'A');
    ok &= Expect(ExchangeWithChannel(channel, "GET_ALL_RULES\n").empty(),
                 "wire payload larger than 2MB is rejected");
    ok &= Expect(logs.size() == 1, "over-limit response is logged once");
    ok &= Expect(!logs.empty() && logs[0].find("rule response too large") != std::string::npos,
                 "over-limit log includes reason");
    ok &= Expect(provider.commands.size() == 6, "provider saw all six commands");
    ok &= Expect(provider.commands[0] == "GET_ALL_RULES", "GET_ALL_RULES was trimmed");
    ok &= Expect(provider.commands[1] == "GET_RULES", "GET_RULES was trimmed");
    ok &= Expect(provider.commands[2] == "UNKNOWN", "unknown command was trimmed");

    if (!ok) {
        return 1;
    }
    std::cout << "amsi_rule_channel_tests passed\n";
    return 0;
}
