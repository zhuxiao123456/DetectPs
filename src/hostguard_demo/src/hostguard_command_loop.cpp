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
        if (command == "state running" || command == "set-state running") {
            std::cout << (app.SetControlState("running") ? "state running set\n" : "state running failed\n");
            continue;
        }
        if (command == "state unload" || command == "set-state unload") {
            std::cout << (app.SetControlState("unload") ? "state unload set\n" : "state unload failed\n");
            continue;
        }
        if (command == "dllhash-clear" || command == "clear-dllhash") {
            std::cout << (app.SetRequiredDllHash("") ? "dllhash cleared\n" : "dllhash clear failed\n");
            continue;
        }
        const std::string dllHashPrefix = "dllhash ";
        if (command.rfind(dllHashPrefix, 0) == 0) {
            const std::string hash = command.substr(dllHashPrefix.size());
            std::cout << (app.SetRequiredDllHash(hash) ? "dllhash set\n" : "dllhash set failed\n");
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
