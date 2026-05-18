#include "hostguard_demo_options.h"

namespace {

bool ParsePipeModeFlag(const std::string& value, HostGuardPipeMode& mode)
{
    if (value == "--demo-pipes") {
        mode = HostGuardPipeMode::Demo;
        return true;
    }
    if (value == "--production-pipes") {
        mode = HostGuardPipeMode::Production;
        return true;
    }
    return false;
}

} // namespace

bool ParseHostGuardDemoOptions(int argc,
                               const char* const* argv,
                               HostGuardDemoOptions& options,
                               std::string& error)
{
    if (argc != 4) {
        error = "usage: " + HostGuardDemoUsage();
        return false;
    }

    HostGuardPipeMode mode = HostGuardPipeMode::Demo;
    if (!ParsePipeModeFlag(argv[3], mode)) {
        error = "pipe mode must be --demo-pipes or --production-pipes";
        return false;
    }

    options.rulesPath = argv[1];
    options.logDir = argv[2];
    ApplyHostGuardPipeMode(options, mode);
    return true;
}

std::string HostGuardDemoUsage()
{
    return "hostguard_demo.exe <rules.json> <log_dir> (--demo-pipes|--production-pipes)";
}
