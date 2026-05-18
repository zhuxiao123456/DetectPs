#pragma once

#include <string>

namespace hostguard_demo {

std::string JoinPath(const std::string& dir, const std::string& name);
std::string DailyJsonlPath(const std::string& logDir, const std::string& prefix);
bool EnsureDirectory(const std::string& path);

} // namespace hostguard_demo
