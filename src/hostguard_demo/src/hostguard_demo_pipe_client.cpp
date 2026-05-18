#include "hostguard_pipe_client.h"

#include <iostream>
#include <string>

int main(int argc, char** argv)
{
    HostGuardPipeClientOptions options;
    std::string error;
    if (!ParseHostGuardPipeClientOptions(argc, argv, options, error)) {
        std::cerr << error << '\n';
        return 2;
    }

    std::string response;
    if (!RunHostGuardPipeClient(options, response, error)) {
        std::cerr << error << '\n';
        return 1;
    }

    if (!response.empty()) {
        std::cout << response;
    }
    return 0;
}
