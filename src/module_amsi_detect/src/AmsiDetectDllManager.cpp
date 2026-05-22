//
// Created by y00969037 on 2026/5/21.
//

#include "AmsiDetectDllManager.h"

#include "ExecuteCmdUtils.h"

#include "AmsiDetectGlobalParam.h"

namespace Engine {
    using namespace SDK;
    using namespace AmsiDetect;

    AmsiDetectDllManager::AmsiDetectDllManager(const std::string &amsiDllFilePath): m_amsiDllFilePath(amsiDllFilePath)
    {
    }

    AmsiDetectDllManager::~AmsiDetectDllManager()
    {
    }

    bool AmsiDetectDllManager::RegisterAmsiProvider()
    {
        std::vector<std::string> args;
        args.emplace_back("/s");
        args.emplace_back(m_amsiDllFilePath);
        int exitCode = 0;
        int rv = ExecuteCmdUtils::ExecuteCmd("regsvr32", args, exitCode);
        if(!IS_EXEC_SUCCESS(rv)) {
            ErrorLog(GetLoggerPtr(), "Exec register amsi cmd failed.");
            return false;
        }

        InfoLog(GetLoggerPtr(), "Register amsi success.");
        return true;
    }

    bool AmsiDetectDllManager::UnregisterAmsiProvider()
    {
        std::vector<std::string> args;
        args.emplace_back("/s");
        args.emplace_back("/u");
        args.emplace_back(m_amsiDllFilePath);
        int exitCode = 0;
        int rv = ExecuteCmdUtils::ExecuteCmd("regsvr32", args, exitCode);
        if(!IS_EXEC_SUCCESS(rv)) {
            ErrorLog(GetLoggerPtr(), "Exec unregister amsi cmd failed.");
            return false;
        }

        InfoLog(GetLoggerPtr(), "Unregister amsi success.");
        return true;
    }

}