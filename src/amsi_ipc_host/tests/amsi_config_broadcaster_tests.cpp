#include "amsi_config_broadcaster.h"
#include "amsi_pipe_names.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <iostream>
#include <string>
#include <thread>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << "FAIL: " << message << "\n";
        return false;
    }
    return true;
}

} // namespace

int main()
{
    bool ok = true;

    ok &= Expect(static_cast<unsigned char>(amsi_ipc::AmsiControlSignal::Reload) == 0x01,
                 "reload signal remains 0x01");
    ok &= Expect(static_cast<unsigned char>(amsi_ipc::AmsiControlSignal::Unload) == 0x02,
                 "unload signal remains 0x02");
    ok &= Expect(static_cast<unsigned char>(amsi_ipc::AmsiControlSignal::PauseDetection) == 0x03,
                 "pause detection signal remains 0x03");
    ok &= Expect(static_cast<unsigned char>(amsi_ipc::AmsiControlSignal::ResumeDetection) == 0x04,
                 "resume detection signal remains 0x04");
    ok &= Expect(std::wstring(amsi_ipc::kConfigPipeName) == LR"(\\.\pipe\amsi_detect_config)",
                 "config pipe name remains amsi_detect_config");

    amsi_ipc::AmsiConfigBroadcaster broadcaster(
        LR"(\\.\pipe\amsi_detect_config_unit_test_no_listener)");
    const auto reload = broadcaster.Broadcast(amsi_ipc::AmsiControlSignal::Reload, 4, 1);
    const auto pause = broadcaster.Broadcast(amsi_ipc::AmsiControlSignal::PauseDetection, 4, 1);
    const auto resume = broadcaster.Broadcast(amsi_ipc::AmsiControlSignal::ResumeDetection, 4, 1);

    ok &= Expect(reload.reached == 0, "reload broadcast with no listener reaches zero clients");
    ok &= Expect(reload.lastError != 0, "reload broadcast with no listener records last error");
    ok &= Expect(pause.reached == 0, "pause broadcast with no listener reaches zero clients");
    ok &= Expect(pause.lastError != 0, "pause broadcast with no listener records last error");
    ok &= Expect(resume.reached == 0, "resume broadcast with no listener reaches zero clients");
    ok &= Expect(resume.lastError != 0, "resume broadcast with no listener records last error");

    const std::wstring serverPipeName =
        LR"(\\.\pipe\amsi_detect_config_unit_test_server_)" + std::to_wstring(GetCurrentProcessId());
    amsi_ipc::AmsiConfigBroadcaster serverBroadcaster(serverPipeName);
    ok &= Expect(serverBroadcaster.Start(), "config broadcaster starts Host-owned pipe server");

    std::atomic<int> received{-1};
    std::thread client([&]() {
        if (!WaitNamedPipeW(serverPipeName.c_str(), 1000)) {
            received.store(-2);
            return;
        }
        HANDLE pipe = CreateFileW(serverPipeName.c_str(),
                                  GENERIC_READ,
                                  0,
                                  nullptr,
                                  OPEN_EXISTING,
                                  0,
                                  nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            received.store(-3);
            return;
        }
        unsigned char signal = 0;
        DWORD readBytes = 0;
        if (!ReadFile(pipe, &signal, 1, &readBytes, nullptr) || readBytes != 1) {
            CloseHandle(pipe);
            received.store(-4);
            return;
        }
        CloseHandle(pipe);
        received.store(static_cast<int>(signal));
    });

    Sleep(100);
    const auto serverReload = serverBroadcaster.Broadcast(amsi_ipc::AmsiControlSignal::Reload, 4, 1000);
    client.join();
    serverBroadcaster.Stop();

    ok &= Expect(serverReload.reached == 1, "Host-owned config broadcaster reaches connected client");
    ok &= Expect(received.load() == 0x01, "connected config client receives reload byte");

    if (!ok) {
        return 1;
    }

    std::cout << "amsi_config_broadcaster_tests passed\n";
    return 0;
}
