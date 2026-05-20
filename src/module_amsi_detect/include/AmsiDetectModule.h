//
// Created by y00969037 on 2026/5/19.
//

#ifndef CSA_ENGINE_AMSI_DETECT_MODULE_H
#define CSA_ENGINE_AMSI_DETECT_MODULE_H

#include "Module.h"
#include "LoggerDefine.h"
#include "AmsiDetectTask.h"

namespace Engine {
    class AmsiDetectModule : public Framework::Module {
    public:
        AmsiDetectModule();
        ~AmsiDetectModule() override;

        int Init() override;
        void UnInit() override;

    protected:
        Framework::Policy *RefreshFeaturePolicy(const std::string &featureName, const std::string &policyStr,
                                                Framework::Policy *&oldPolicy);

        int DownloadAmsiFeatureLibrary(const std::string &args);

    private:
        AmsiDetectTask *m_pDetectTask{nullptr};

        // 保证同一时间只下载一次.
        SDK::LockUtils::MutexLock m_downloadLock;
    };

}

#ifdef __cplusplus
extern "C" {
#endif

Framework::Module *CreateModule();

#ifdef __cplusplus
}
#endif

#endif //CSA_ENGINE_AMSI_DETECT_MODULE_H
