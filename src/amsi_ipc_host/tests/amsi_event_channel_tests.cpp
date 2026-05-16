#include "amsi_event_channel.h"

#include <iostream>
#include <string>
#include <vector>

namespace {

class FakeEventSink : public amsi_ipc::IAmsiEventSink {
public:
    void OnEventLine(const amsi_ipc::AmsiEventLine& event) override
    {
        payloads.push_back(event.payload);
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

void SendToChannel(amsi_ipc::AmsiEventChannel& channel, const std::string& payload)
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
    FakeEventSink sink;
    amsi_ipc::AmsiEventChannel channel(sink);

    SendToChannel(channel, R"({"cat":"Detection","msg":"a\\b\"c"})");
    ok &= Expect(sink.payloads.size() == 1, "normal payload reaches sink");
    ok &= Expect(sink.payloads[0] == R"({"cat":"Detection","msg":"a\\b\"c"})",
                 "normal payload is unchanged");

    const std::string utf8 = u8"{\"msg\":\"中文🙂\"}\nkeep-middle-newline";
    SendToChannel(channel, utf8);
    ok &= Expect(sink.payloads.size() == 2, "utf8 payload reaches sink");
    ok &= Expect(sink.payloads[1] == utf8, "utf8 and embedded newline are unchanged");

    SendToChannel(channel, "not-json");
    ok &= Expect(sink.payloads.size() == 3, "non-json payload reaches sink");
    ok &= Expect(sink.payloads[2] == "not-json", "non-json payload is unchanged");

    SendToChannel(channel, "");
    ok &= Expect(sink.payloads.size() == 3, "empty payload does not call sink");

    if (!ok) {
        return 1;
    }
    std::cout << "amsi_event_channel_tests passed\n";
    return 0;
}
