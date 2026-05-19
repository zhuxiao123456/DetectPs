#include "amsi_config_broadcaster.h"
#include "amsi_pipe_names.h"

#include <iostream>
#include <string>

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

    if (!ok) {
        return 1;
    }

    std::cout << "amsi_config_broadcaster_tests passed\n";
    return 0;
}
