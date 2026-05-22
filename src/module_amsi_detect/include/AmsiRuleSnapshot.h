//
// Created by Codex on 2026/5/21.
//

#ifndef CSA_ENGINE_AMSI_RULE_SNAPSHOT_H
#define CSA_ENGINE_AMSI_RULE_SNAPSHOT_H

#include <string>

namespace Engine {

    struct AmsiRuleSnapshot {
        std::string allRulesJson;
        std::string amsiRulesJson;
        std::string version;
        std::string hash;
    };

    bool LoadRuleSnapshot(const std::string &rulePath,
                          const std::string &version,
                          AmsiRuleSnapshot &snapshot,
                          std::string &error);

}

#endif //CSA_ENGINE_AMSI_RULE_SNAPSHOT_H
