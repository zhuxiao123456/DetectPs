//
// Created by y00969037 on 2026/5/19.
//

#ifndef CSA_ENGINE_AMSI_DETECT_POLICY_H
#define CSA_ENGINE_AMSI_DETECT_POLICY_H

#include <set>

#include "JsonUtils.h"

#include "Policy.h"

namespace Engine {

    constexpr int DEFAULT_AMSI_MAX_SCAN_CONTENT_BYTES = 8192;
    constexpr int MIN_AMSI_MAX_SCAN_CONTENT_BYTES = 1024;
    constexpr int MAX_AMSI_MAX_SCAN_CONTENT_BYTES = 65536;

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

    private:
        bool m_autoBlock = false;
        int m_maxScanContentBytes = DEFAULT_AMSI_MAX_SCAN_CONTENT_BYTES;
        std::set<std::string> m_trustProcess;
    };
}

#endif //CSA_ENGINE_AMSI_DETECT_POLICY_H
