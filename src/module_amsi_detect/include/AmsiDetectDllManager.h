//
// Created by y00969037 on 2026/5/21.
//

#ifndef CSA_ENGINE_AMSI_DETECT_DLL_MANAGER_H
#define CSA_ENGINE_AMSI_DETECT_DLL_MANAGER_H

#include <string>

namespace Engine {
    class AmsiDetectDllManager {
    public:
        AmsiDetectDllManager(const std::string &amsiDllFilePath);
        ~AmsiDetectDllManager();

        bool RegisterAmsiProvider();
        bool UnregisterAmsiProvider();

    private:
        // dll 路径.
        std::string m_amsiDllFilePath;
    };
}

#endif //CSA_ENGINE_AMSI_DETECT_DLL_MANAGER_H
