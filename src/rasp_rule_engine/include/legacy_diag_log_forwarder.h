#pragma once

#include <cstdint>
#include <limits>
#include <string_view>

enum class LegacyDiagForwardStatus {
    Sent,
    EmptyPayload,
    PayloadTooLarge,
    PipeUnavailable,
    AccessDenied,
    WriteFailed
};

class ILegacyDiagBytesWriter {
public:
    virtual ~ILegacyDiagBytesWriter() = default;
    virtual LegacyDiagForwardStatus Send(std::string_view payload) = 0;
};

class LegacyDiagLogForwarder {
public:
    explicit LegacyDiagLogForwarder(ILegacyDiagBytesWriter& writer);

    LegacyDiagForwardStatus Forward(std::string_view compactJson) const;

private:
    ILegacyDiagBytesWriter& writer_;
};
