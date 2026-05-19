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
    std::string version;
    std::string hash;
    std::vector<std::string> trustProcessPaths;
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
    struct Parser {
        const char* p;
        const char* end;

        Parser(const char* data, size_t len) : p(data), end(data + len) {}

        bool ok() const { return p < end; }
        void skip_ws();
        bool peek(char c);
        bool consume(char c);
        bool read_string(std::string& out);
        bool read_bool(bool& out);
        bool read_int(int& out);
        bool read_string_array(std::vector<std::string>& out);
        bool read_regex_check_array(std::vector<RegexCheck>& out);
        void skip_value();
        void skip_array();
        void skip_object();
    };

    RuleParseResult Parse(std::string_view json,
                          const IRuleObjectFactory& factory,
                          IRuleExtensionParser& extensionParser) const;
};
