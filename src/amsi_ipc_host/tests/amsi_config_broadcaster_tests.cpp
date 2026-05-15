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
    ok &= Expect(std::wstring(amsi_ipc::kConfigPipeName) == LR"(\\.\pipe\amsi_detect_config)",
                 "config pipe name remains amsi_detect_config");

    amsi_ipc::AmsiConfigBroadcaster broadcaster(
        LR"(\\.\pipe\amsi_detect_config_unit_test_no_listener)");
    const auto result = broadcaster.Broadcast(amsi_ipc::AmsiControlSignal::Reload, 4, 1);

    ok &= Expect(result.reached == 0, "broadcast with no listener reaches zero clients");
    ok &= Expect(result.lastError != 0, "broadcast with no listener records last error");

    if (!ok) {
        return 1;
    }

    std::cout << "amsi_config_broadcaster_tests passed\n";
    return 0;
}
