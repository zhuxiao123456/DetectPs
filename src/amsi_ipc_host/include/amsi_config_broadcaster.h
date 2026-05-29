#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

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
    ~AmsiConfigBroadcaster();

    AmsiConfigBroadcaster(const AmsiConfigBroadcaster&) = delete;
    AmsiConfigBroadcaster& operator=(const AmsiConfigBroadcaster&) = delete;

    bool Start();
    void Stop();

    AmsiBroadcastResult Broadcast(AmsiControlSignal signal,
                                  int maxListeners,
                                  std::uint32_t timeoutMs) const;

private:
    static unsigned long __stdcall AcceptThreadProc(void* param);
    void AcceptLoop();
    void CloseClientsLocked();
    void WakeAcceptThread() const;

    std::wstring configPipeName_;
    void* acceptThread_ = nullptr;
    void* stopEvent_ = nullptr;
    mutable std::mutex mutex_;
    mutable std::vector<void*> clients_;
    bool running_ = false;
};

} // namespace amsi_ipc
