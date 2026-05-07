#include "legacy_diag_log_forwarder.h"

#include <iostream>
#include <string>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition)
        std::cerr << "FAIL: " << message << "\n";
    return condition;
}

class FakeWriter final : public ILegacyDiagBytesWriter {
public:
    LegacyDiagForwardStatus nextStatus = LegacyDiagForwardStatus::Sent;
    int callCount = 0;
    std::string capturedPayload;

    LegacyDiagForwardStatus Send(std::string_view payload) override
    {
        ++callCount;
        capturedPayload.assign(payload.data(), payload.size());
        return nextStatus;
    }
};

} // namespace

int main()
{
    {
        FakeWriter writer;
        LegacyDiagLogForwarder forwarder(writer);

        LegacyDiagForwardStatus status = forwarder.Forward("");
        if (!Expect(status == LegacyDiagForwardStatus::EmptyPayload, "empty payload is rejected"))
            return 1;
        if (!Expect(writer.callCount == 0, "empty payload does not call writer"))
            return 1;
    }

    {
        FakeWriter writer;
        LegacyDiagLogForwarder forwarder(writer);
        const std::string payload = "{\"cat\":\"diag\"}";

        LegacyDiagForwardStatus status = forwarder.Forward(payload);
        if (!Expect(status == LegacyDiagForwardStatus::Sent, "sent status is returned"))
            return 1;
        if (!Expect(writer.callCount == 1, "writer is called once"))
            return 1;
        if (!Expect(writer.capturedPayload == payload, "payload is forwarded unchanged"))
            return 1;
        if (!Expect(!writer.capturedPayload.empty() && writer.capturedPayload.back() == '}',
                    "forwarder does not append newline"))
            return 1;
    }

    {
        FakeWriter writer;
        writer.nextStatus = LegacyDiagForwardStatus::PipeUnavailable;
        LegacyDiagLogForwarder forwarder(writer);

        LegacyDiagForwardStatus status = forwarder.Forward("{\"cat\":\"diag\"}");
        if (!Expect(status == LegacyDiagForwardStatus::PipeUnavailable, "PipeUnavailable is passed through"))
            return 1;
    }

    {
        FakeWriter writer;
        writer.nextStatus = LegacyDiagForwardStatus::AccessDenied;
        LegacyDiagLogForwarder forwarder(writer);

        LegacyDiagForwardStatus status = forwarder.Forward("{\"cat\":\"diag\"}");
        if (!Expect(status == LegacyDiagForwardStatus::AccessDenied, "AccessDenied is passed through"))
            return 1;
    }

    {
        FakeWriter writer;
        writer.nextStatus = LegacyDiagForwardStatus::WriteFailed;
        LegacyDiagLogForwarder forwarder(writer);

        LegacyDiagForwardStatus status = forwarder.Forward("{\"cat\":\"diag\"}");
        if (!Expect(status == LegacyDiagForwardStatus::WriteFailed, "WriteFailed is passed through"))
            return 1;
    }

    {
        FakeWriter writer;
        LegacyDiagLogForwarder forwarder(writer);
        const std::string payload = "not-json";

        LegacyDiagForwardStatus status = forwarder.Forward(payload);
        if (!Expect(status == LegacyDiagForwardStatus::Sent, "forwarder does not parse JSON"))
            return 1;
        if (!Expect(writer.capturedPayload == payload, "non-JSON payload is forwarded unchanged"))
            return 1;
    }

    return 0;
}

