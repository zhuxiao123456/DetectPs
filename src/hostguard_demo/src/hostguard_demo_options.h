#pragma once

#include "hostguard_demo_app.h"

#include <string>

bool ParseHostGuardDemoOptions(int argc,
                               const char* const* argv,
                               HostGuardDemoOptions& options,
                               std::string& error);

std::string HostGuardDemoUsage();
