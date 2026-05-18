#include "hostguard_command_loop.h"
#include "hostguard_demo_app.h"
#include "hostguard_demo_options.h"
#include "hostguard_paths.h"

#include "sentry_log.h"

#include <iostream>
#include <string>

int main(int argc, char** argv)
{
    HostGuardDemoOptions options;
    std::string error;
    if (!ParseHostGuardDemoOptions(argc, argv, options, error)) {
        std::cerr << error << '\n';
        return 2;
    }

    hostguard_demo::EnsureDirectory(options.logDir);
    SentryLog_Initialize(options.logDir.c_str());

    HostGuardDemoApp app(options);
    if (!app.Start()) {
        std::cerr << "failed to start hostguard_demo";
        if (!app.start_error().empty()) {
            std::cerr << ": " << app.start_error();
        }
        std::cerr << '\n';
        return 1;
    }

    app.PrintStatus(std::cout);
    return RunHostGuardCommandLoop(app);
}
