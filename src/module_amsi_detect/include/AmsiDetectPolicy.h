//
// Created by y00969037 on 2026/5/19.
//

#ifndef CSA_ENGINE_AMSI_DETECT_POLICY_H
#define CSA_ENGINE_AMSI_DETECT_POLICY_H

#include <set>

#include "JsonUtils.h"

#include "Policy.h"

namespace Engine {

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

    private:
        bool m_autoBlock = false;
        std::set<std::string> m_trustProcess;
    };
}

#endif //CSA_ENGINE_AMSI_DETECT_POLICY_H
