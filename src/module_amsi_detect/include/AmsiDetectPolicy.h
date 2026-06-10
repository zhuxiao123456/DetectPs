//
// Created by y00969037 on 2026/5/19.
//

#ifndef CSA_ENGINE_AMSI_DETECT_POLICY_H
#define CSA_ENGINE_AMSI_DETECT_POLICY_H

#include <set>

#include "JsonUtils.h"

#include "Policy.h"

namespace Engine {

    struct ScanRateLimit {
        bool enabled = false;
        int windowMs = 1000;
        int maxScans = 300;
        double bypassRatioAfterLimit = 0.8;
    };

    constexpr int DEFAULT_AMSI_MAX_SCAN_CONTENT_BYTES = 8192;

    class AmsiDetectPolicy : public Framework::FeaturePolicy {
    public:
        explicit AmsiDetectPolicy(const std::string &featureName);
        virtual ~AmsiDetectPolicy();

        bool Parse(const std::string &policyContent) override;
    };

    class AmsiDetectTaskPolicy : public Framework::TaskPolicy {
    public:
        explicit AmsiDetectTaskPolicy(const std::string &name);
        virtual ~AmsiDetectTaskPolicy();

        bool Parse(const std::string &policyContent) override;

        bool IsAutoBlock() const {
            return m_autoBlock;
        }

        const std::set<std::string> &GetTrustProcess() {
            return m_trustProcess;
        }

        int GetMaxScanContentBytes() const {
            return m_maxScanContentBytes;
        }

        int GetAuditMaxEventsPerScan() const {
            return m_auditMaxEventsPerScan;
        }

        int GetTotalScanTimeoutMs() const {
            return m_totalScanTimeoutMs;
        }

        uint32_t GetMaxAlarmCntPerHour() const {
                return m_maxAlarmCntPerHour;
        }


        const ScanRateLimit &GetScanRateLimit() const {
            return m_scanRateLimit;
        }
    private:
        bool m_autoBlock = false;
        uint32_t m_maxAlarmCntPerHour{100};
        int m_maxScanContentBytes = DEFAULT_AMSI_MAX_SCAN_CONTENT_BYTES;
        int m_auditMaxEventsPerScan = 3;
        int m_totalScanTimeoutMs = 1000;
        std::set<std::string> m_trustProcess;
        ScanRateLimit m_scanRateLimit;
    };
}

#endif //CSA_ENGINE_AMSI_DETECT_POLICY_H
