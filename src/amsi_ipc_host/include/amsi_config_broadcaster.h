#pragma once

#include <cstdint>
#include <string>

namespace amsi_ipc {

enum class AmsiControlSignal : std::uint8_t {
    Reload = 0x01,
    Unload = 0x02,
    PauseDetection = 0x03,
    ResumeDetection = 0x04,
};

struct AmsiBroadcastResult {
    int reached = 0;
    std::uint32_t lastError = 0;
};

class AmsiConfigBroadcaster {
public:
    explicit AmsiConfigBroadcaster(std::wstring configPipeName);

    AmsiBroadcastResult Broadcast(AmsiControlSignal signal,
                                  int maxListeners,
                                  std::uint32_t timeoutMs) const;

private:
    std::wstring configPipeName_;
};

} // namespace amsi_ipc
