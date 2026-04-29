#pragma once

#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "rasp_rule_base.h"

struct RuleParseResult {
    bool ok = false;
    std::vector<std::unique_ptr<RaspRuleBase>> rules;
    std::string libSource;
    std::string error;
};

class IRuleObjectFactory {
public:
    virtual ~IRuleObjectFactory() = default;
    virtual RaspRuleBase* CreateRule() const = 0;
};

class IRuleExtensionParser {
public:
    virtual ~IRuleExtensionParser() = default;
    virtual void ParseRuleExtension(const std::string& key,
                                    void* parserContext,
                                    RaspRuleBase& rule) = 0;
};

class RuleJsonParser {
public:
    RuleParseResult Parse(std::string_view json,
                          const IRuleObjectFactory& factory,
                          IRuleExtensionParser& extensionParser) const;
};
