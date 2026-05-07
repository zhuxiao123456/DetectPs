#include "legacy_diag_log_forwarder.h"

LegacyDiagLogForwarder::LegacyDiagLogForwarder(ILegacyDiagBytesWriter& writer)
    : writer_(writer)
{
}

LegacyDiagForwardStatus LegacyDiagLogForwarder::Forward(std::string_view compactJson) const
{
    if (compactJson.empty()) {
        return LegacyDiagForwardStatus::EmptyPayload;
    }

    if (compactJson.size() > static_cast<size_t>(std::numeric_limits<uint32_t>::max())) {
        return LegacyDiagForwardStatus::PayloadTooLarge;
    }

    return writer_.Send(compactJson);
}

