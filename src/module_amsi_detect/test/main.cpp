#include <cstdio>
#include <csignal>
#include <string>
#include <iostream>

#include "gtest/gtest.h"

#include "LoggerDefine.h"
#include "ConfigUtils.h"
#include "DirUtils.h"
#include "StrUtils.h"
#include "ValueUtils.h"
#include "DumpStackUtils.h"

#include "CsaEngine.h"
#include "MsgIdDefine.h"
#include "GodMessage.h"

using namespace SDK;
using namespace Framework;
using namespace std;

static void InitLogger();
static void RegisterSignal();

class EngineEnvironment : public testing::Environment
{
public:
    virtual void SetUp()
    {
        std::cout << "EngineEnvironment SetUP begin" << std::endl;

        InitLogger();
        RegisterSignal();

        std::vector<std::string> args;
        args.push_back("hostguard");
        if (CsaEngineRef.Init(args)< 0) {
            std::cout << "Engine init failed." << std::endl;
        }

        std::cout << "EngineEnvironment SetUP end" << std::endl;
    }

    virtual void TearDown()
    {
        std::cout << "EngineEnvironment TearDown begin" << std::endl;

        std::string msgBody = "{\"msg_id\": \"";
        msgBody.append(ENGINE_GRACE_EXIT);
        msgBody.append("\", \"msg\":{\"command\":\"exit from kill\"}}");
        CsaEngineRef.EnqueueMsg(new GodMessage(msgBody));

        std::cout << "EngineEnvironment TearDown end" << std::endl;
    }
};

GTEST_API_ int main(int argc, char **argv)
{
    printf("Running main() from %s\n", __FILE__);

    RegisterSignal();

    testing::AddGlobalTestEnvironment(new EngineEnvironment);
    testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}

static void InitLogger()
{
    std::string path;
    SDK::PathUtils::GetInstallationPath(path);

    bool logMerge = true;
    std::string logLevel = "info";
    std::string logPath = path + "log";
    std::string logConfPath = path + "conf" + PathUtils::separator() + "logger.conf";
    std::string logFileSize = "10 M";
    int rolls = 8;

    SDK::ConfigUtils conf;
    if (conf.LoadConfigFile(logConfPath) == 0) {
        logMerge = conf.GetBoolValue("merge", true);
        logLevel = conf.GetStringValue("level", "info");

        // 输入参数合法性校验.
        std::string confLogPath = conf.GetStringValue("path", path + "log");
        if (DirUtils::IsDir(confLogPath)) {
            logPath = confLogPath;
        }

        // log size
        std::string confLogFileSize = conf.GetStringValue("size", logFileSize);
        if (confLogFileSize != logFileSize) {
            std::vector<std::string> v;
            StrUtils::EasySplit(confLogFileSize, " ", v);
            if (v.size() == 2 && v[1] == "M") {
                uint32_t size = ValueUtils::GetValidUint32Value(v[0], 1, 20, 10);
                logFileSize = std::to_string(size) + " M";
            }
        }

        rolls = conf.GetIntValue("rolls", rolls);
        rolls = ValueUtils::GetValidUint32Value(rolls, 1, 20, 8);
    }

    LoggerRef.SetLogPath(logPath);
    LoggerRef.SetMainLogFileName("hostguard.log");
    LoggerRef.SetLevel(logLevel);
    LoggerRef.SetMerge(logMerge);
    LoggerRef.SetLogFileSize(logFileSize);
    LoggerRef.SetLogRolls(rolls);
#ifdef DEBUG
    LoggerRef.SetDebugMode(true);
#endif
    LoggerRef.LoggerInit();
}

static void DumpStack(int signo)
{
    signal(SIGSEGV, SIG_DFL);
    signal(SIGABRT, SIG_DFL);

    DumpStackUtils::DumpStack(nullptr, "hostguard");

    signal(signo, SIG_DFL);
    raise(signo);
}

static void RegisterSignal()
{
    if (signal(SIGSEGV, DumpStack) == SIG_ERR) {
        std::cout << "Register SIGSEGV callback failed." << endl;
    }
    if (signal(SIGABRT, DumpStack) == SIG_ERR) {
        std::cout << "Register SIGABRT callback failed." << endl;
    }
}