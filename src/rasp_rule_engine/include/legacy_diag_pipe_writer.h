#pragma once

#include "legacy_diag_log_forwarder.h"

#include <string_view>

class LegacyDiagPipeWriter final : public ILegacyDiagBytesWriter {
public:
    LegacyDiagForwardStatus Send(std::string_view payload) override;
};

