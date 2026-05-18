#include "hostguard_paths.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>

namespace hostguard_demo {

std::string JoinPath(const std::string& dir, const std::string& name)
{
    if (dir.empty()) {
        return name;
    }
    const char last = dir.back();
    if (last == '\\' || last == '/') {
        return dir + name;
    }
    return dir + "\\" + name;
}

std::string DailyJsonlPath(const std::string& logDir, const std::string& prefix)
{
    SYSTEMTIME st = {};
    GetSystemTime(&st);

    char date[16] = {};
    _snprintf_s(date,
                sizeof(date),
                _TRUNCATE,
                "%04d-%02d-%02d",
                st.wYear,
                st.wMonth,
                st.wDay);

    return JoinPath(logDir, prefix + "-" + date + ".jsonl");
}

bool EnsureDirectory(const std::string& path)
{
    if (path.empty()) {
        return false;
    }
    if (CreateDirectoryA(path.c_str(), nullptr)) {
        return true;
    }
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

} // namespace hostguard_demo
