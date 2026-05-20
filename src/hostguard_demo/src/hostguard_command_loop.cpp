#include "hostguard_command_loop.h"

#include "hostguard_demo_app.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <string>

namespace {

std::string NormalizeCommand(std::string command)
{
    command.erase(std::remove_if(command.begin(),
                                 command.end(),
                                 [](unsigned char ch) { return ch == '\r' || ch == '\n'; }),
                  command.end());
    std::transform(command.begin(),
                   command.end(),
                   command.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return command;
}

} // namespace

int RunHostGuardCommandLoop(HostGuardDemoApp& app)
{
    std::string command;
    while (std::cout << "hostguard_demo> " && std::getline(std::cin, command)) {
        command = NormalizeCommand(command);
        if (command == "quit" || command == "exit") {
            app.Stop();
            return 0;
        }
        if (command == "status") {
            app.PrintStatus(std::cout);
            continue;
        }
        if (command == "reload") {
            std::cout << (app.Reload() ? "reload sent\n" : "reload failed\n");
            continue;
        }
        if (command == "pause-detection" || command == "policy-off") {
            std::cout << (app.PauseDetection() ? "pause-detection sent\n" : "pause-detection failed\n");
            continue;
        }
        if (command == "resume-detection" || command == "policy-on") {
            std::cout << (app.ResumeDetection() ? "resume-detection sent\n" : "resume-detection failed\n");
            continue;
        }
        if (command == "unload") {
            std::cout << (app.Unload() ? "unload sent\n" : "unload failed\n");
            continue;
        }
        if (!command.empty()) {
            std::cout << "unknown command: " << command << '\n';
        }
    }
    app.Stop();
    return 0;
}
