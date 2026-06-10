//
// Created by z00840245 on 2026/5/26.
//

#ifndef CSA_ENGINE_AMSI_EVENT_PROCESSOR_H
#define CSA_ENGINE_AMSI_EVENT_PROCESSOR_H

#include <string>

#include "CommonDefine.h"

#define AmsiEventProcessorRef  Engine::AmsiEventProcessor::GetInstance()

namespace Engine {
    class AmsiEventProcessor {
        DECLARE_UNCOPYABLE(AmsiEventProcessor)
        DECLARE_SINGLETON_CROSS_LIB(AmsiEventProcessor)

    public:
        void SetMaxAlarmCntPerHour(uint32_t maxAlarmCntPerHour) {
            m_maxAlarmCntPerHour = maxAlarmCntPerHour;
        }

        bool ProcessDetectionEvent(const std::string &rawJson, std::string &error);

        bool IsAlarmCacheFull();

        void AddAlarmTimeToCache(time_t alarmTime);

    private:
        bool ClearAlarmTimeCacheList(std::list<time_t> &pathAlarmTimeList);

    private:
        // 每小时最多上报告警数.
        uint32_t m_maxAlarmCntPerHour{100};

        // agent一小时内的告警时间列表，一小时内告警超过阈值则不再发送告警，防止告警过多服务端过载.
        std::list<time_t> m_agentAlarmTimeCache;
    };
}

#endif // CSA_ENGINE_AMSI_EVENT_PROCESSOR_H
