#include "amsi_control_status_channel.h"

#include <iostream>
#include <string>
#include <vector>

namespace {

class FakeControlStatusSink : public amsi_ipc::IAmsiControlStatusSink {
public:
    void OnControlStatusLine(const amsi_ipc::AmsiControlStatusLine& status) override
    {
        payloads.push_back(status.payload);
    }

    std::vector<std::string> payloads;
};

bool Expect(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << "FAIL: " << message << "\n";
        return false;
    }
    return true;
}

void SendToChannel(amsi_ipc::AmsiControlStatusChannel& channel, const std::string& payload)
{
    HANDLE readPipe = INVALID_HANDLE_VALUE;
    HANDLE writePipe = INVALID_HANDLE_VALUE;
    if (!CreatePipe(&readPipe, &writePipe, nullptr, 65536)) {
        return;
    }

    if (!payload.empty()) {
        DWORD written = 0;
        WriteFile(writePipe, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr);
    }
    CloseHandle(writePipe);

    channel.HandleClient(readPipe);
    CloseHandle(readPipe);
}

} // namespace

int main()
{
    bool ok = true;
    FakeControlStatusSink sink;
    amsi_ipc::AmsiControlStatusChannel channel(sink);

    const std::string ruleLoadResult =
        R"({"type":"RULE_LOAD_RESULT","success":true,"requestedVersion":"","activeVersion":"","errorCode":0})";
    SendToChannel(channel, ruleLoadResult);
    ok &= Expect(sink.payloads.size() == 1, "RULE_LOAD_RESULT payload reaches sink");
    ok &= Expect(sink.payloads[0] == ruleLoadResult, "RULE_LOAD_RESULT payload is unchanged");

    const std::string multiline = "{\"type\":\"RULE_LOAD_RESULT\"}\n{\"extra\":true}";
    SendToChannel(channel, multiline);
    ok &= Expect(sink.payloads.size() == 2, "embedded newline payload reaches sink");
    ok &= Expect(sink.payloads[1] == multiline, "embedded newline is unchanged");

    const std::string utf8 = std::string("{\"message\":\"control ") +
                             "\xE7\x8A\xB6\xE6\x80\x81" +
                             "\"}";
    SendToChannel(channel, utf8);
    ok &= Expect(sink.payloads.size() == 3, "utf8 payload reaches sink");
    ok &= Expect(sink.payloads[2] == utf8, "utf8 bytes are unchanged");

    SendToChannel(channel, "not-json");
    ok &= Expect(sink.payloads.size() == 4, "non-json payload reaches sink");
    ok &= Expect(sink.payloads[3] == "not-json", "non-json payload is unchanged");

    SendToChannel(channel, "");
    ok &= Expect(sink.payloads.size() == 4, "empty payload does not call sink");

    if (!ok) {
        return 1;
    }
    std::cout << "amsi_control_status_channel_tests passed\n";
    return 0;
}
