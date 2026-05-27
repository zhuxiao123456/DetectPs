//
// Created by z00840245 on 2026/5/26.
//

#ifndef CSA_ENGINE_AMSI_EVENT_PROCESSOR_H
#define CSA_ENGINE_AMSI_EVENT_PROCESSOR_H

#include <string>

namespace Engine {

    class AmsiEventProcessor {
    public:
        static bool ProcessDetectionEvent(const std::string &rawJson, std::string &error);

    private:
        AmsiEventProcessor() = delete;
    };

}

#endif // CSA_ENGINE_AMSI_EVENT_PROCESSOR_H