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
            out.json = R"({"kind":"all"})";
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

    char response[256] = {};
    DWORD bytesRead = 0;
    ReadFile(client, response, static_cast<DWORD>(sizeof(response) - 1), &bytesRead, nullptr);

    CloseHandle(client);
    serverThread.join();

    return std::string(response, bytesRead);
}

} // namespace

int main()
{
    bool ok = true;
    FakeRuleProvider provider;
    amsi_ipc::AmsiRuleChannel channel(provider);

    ok &= Expect(ExchangeWithChannel(channel, "GET_ALL_RULES\n") == R"({"kind":"all"})" "\n",
                 "GET_ALL_RULES returns assembled response with newline");
    ok &= Expect(ExchangeWithChannel(channel, "GET_RULES\r\n") == R"({"kind":"amsi"})" "\n",
                 "GET_RULES returns AMSI-filtered response with newline");
    ok &= Expect(ExchangeWithChannel(channel, "UNKNOWN\n").empty(),
                 "unknown command writes no payload");
    ok &= Expect(provider.commands.size() == 3, "provider saw all three commands");
    ok &= Expect(provider.commands[0] == "GET_ALL_RULES", "GET_ALL_RULES was trimmed");
    ok &= Expect(provider.commands[1] == "GET_RULES", "GET_RULES was trimmed");
    ok &= Expect(provider.commands[2] == "UNKNOWN", "unknown command was trimmed");

    if (!ok) {
        return 1;
    }
    std::cout << "amsi_rule_channel_tests passed\n";
    return 0;
}
