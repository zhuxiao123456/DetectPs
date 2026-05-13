#include "rule_json_parser.h"

#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition)
        std::cerr << "FAIL: " << message << "\n";
    return condition;
}

class TestRuleFactory final : public IRuleObjectFactory {
public:
    RaspRuleBase* CreateRule() const override
    {
        return new RaspRuleBase();
    }
};

class TestExtensionParser final : public IRuleExtensionParser {
public:
    void ParseRuleExtension(const std::string& key,
                            void* parserContext,
                            RaspRuleBase& rule) override
    {
        auto* parser = static_cast<RuleJsonParser::Parser*>(parserContext);
        if (key != "config") {
            parser->skip_value();
            return;
        }

        if (!parser->consume('{'))
            return;

        while (!parser->peek('}') && parser->ok()) {
            std::string ckey;
            if (!parser->read_string(ckey) || !parser->consume(':'))
                break;

            if (ckey == "regexField") {
                parser->read_string(rule.regexField);
            } else if (ckey == "regexPatterns") {
                parser->read_string_array(rule.regexPatterns);
            } else if (ckey == "regexChecks") {
                parser->read_regex_check_array(rule.regexChecks);
            } else if (ckey == "regexCondition") {
                std::string cond;
                parser->read_string(cond);
                rule.regexCondition = (cond == "all") ? RegexCondition::All : RegexCondition::Any;
            } else {
                parser->skip_value();
            }

            parser->consume(',');
        }

        parser->consume('}');
    }
};

RuleParseResult Parse(std::string_view json)
{
    TestRuleFactory factory;
    TestExtensionParser extensionParser;
    RuleJsonParser parser;
    return parser.Parse(json, factory, extensionParser);
}

} // namespace

int main()
{
    {
        const char* json = R"json({
            "ignoredTopLevel": {"nested": [1, 2, 3]},
            "globalLibrariesBase64": ["bGliLW9uZQ==", "bGliLXR3bw=="],
            "rules": [
                {
                    "id": "rule-1",
                    "sensor": "AmsiProvider",
                    "enabled": false,
                    "description": "desc",
                    "severity": "High",
                    "scriptBodyBase64": "c2NyaXB0",
                    "scriptEval": "exclusive",
                    "confidence": 87,
                    "mode": "block",
                    "scriptTimeoutMs": 2,
                    "unknownObject": {"x": ["y"]},
                    "config": {
                        "regexField": "body",
                        "regexPatterns": ["IEX", "DownloadString"],
                        "regexCondition": "all",
                        "regexChecks": [
                            {"id": "ck1", "field": "body", "patterns": ["Invoke"]},
                            {"id": "", "field": "body", "patterns": ["ignored"]},
                            {"id": "ck2", "field": "url", "patterns": []}
                        ],
                        "ignored": {"deep": true}
                    }
                },
                {
                    "id": "",
                    "sensor": "AmsiProvider"
                },
                {
                    "id": "rule-2",
                    "mode": "unknown",
                    "scriptTimeoutMs": 0,
                    "config": {
                        "regexCondition": "any"
                    }
                }
            ]
        })json";

        auto result = Parse(json);
        if (!Expect(result.ok, "normal rule bundle parses"))
            return 1;
        if (!Expect(result.libSource == "lib-one\nlib-two\n", "globalLibrariesBase64 decodes in order"))
            return 1;
        if (!Expect(result.version.empty() && result.hash.empty(), "legacy rules response has empty metadata"))
            return 1;
        if (!Expect(result.rules.size() == 2, "empty id rule is skipped"))
            return 1;

        const auto& first = *result.rules[0];
        if (!Expect(first.id == "rule-1", "id parsed"))
            return 1;
        if (!Expect(first.sensor == "AmsiProvider", "sensor parsed"))
            return 1;
        if (!Expect(!first.enabled, "enabled false parsed"))
            return 1;
        if (!Expect(first.description == "desc", "description parsed"))
            return 1;
        if (!Expect(first.severity == "High", "severity parsed"))
            return 1;
        if (!Expect(first.scriptBodyBase64 == "c2NyaXB0", "script body base64 parsed"))
            return 1;
        if (!Expect(first.scriptEval == "exclusive", "script eval parsed"))
            return 1;
        if (!Expect(first.confidence == 87, "confidence parsed"))
            return 1;
        if (!Expect(first.mode == RaspRuleMode::Block, "block mode parsed"))
            return 1;
        if (!Expect(first.scriptTimeoutInstructions == 100000, "scriptTimeoutMs maps to instructions"))
            return 1;
        if (!Expect(first.regexField == "body", "extension regexField parsed"))
            return 1;
        if (!Expect(first.regexPatterns.size() == 2 && first.regexPatterns[0] == "IEX",
                    "extension regexPatterns parsed"))
            return 1;
        if (!Expect(first.regexCondition == RegexCondition::All, "extension regexCondition all parsed"))
            return 1;
        if (!Expect(first.regexChecks.size() == 1 && first.regexChecks[0].id == "ck1",
                    "extension regexChecks filters incomplete checks"))
            return 1;

        const auto& second = *result.rules[1];
        if (!Expect(second.id == "rule-2", "second rule id parsed"))
            return 1;
        if (!Expect(second.mode == RaspRuleMode::Audit, "unknown mode falls back to audit"))
            return 1;
        if (!Expect(second.scriptTimeoutInstructions == 500000,
                    "non-positive script timeout falls back to default"))
            return 1;
        if (!Expect(second.regexCondition == RegexCondition::Any,
                    "non-all regex condition falls back to any"))
            return 1;
    }

    {
        const char* json = R"json({
            "version": "rules-v42",
            "hash": "sha256:abc123",
            "globalLibrariesBase64": "bGliLWVudmVsb3Bl",
            "bundle": {
                "rules": [
                    {
                        "id": "enveloped-rule",
                        "sensor": "AmsiProvider",
                        "mode": "block",
                        "config": {
                            "regexField": "body",
                            "regexPatterns": ["FromEnvelope"]
                        }
                    }
                ],
                "ignoredBundleField": {"nested": true}
            }
        })json";

        auto result = Parse(json);
        if (!Expect(result.ok, "envelope bundle rules parse"))
            return 1;
        if (!Expect(result.version == "rules-v42", "envelope version is passed through"))
            return 1;
        if (!Expect(result.hash == "sha256:abc123", "envelope hash is passed through"))
            return 1;
        if (!Expect(result.libSource == "lib-envelope", "envelope global library decodes"))
            return 1;
        if (!Expect(result.rules.size() == 1 && result.rules[0]->id == "enveloped-rule",
                    "bundle.rules populates rules"))
            return 1;
    }

    {
        auto result = Parse(R"json({"version":"rules-v43","bundle":{"rules":[{"id":"r"}]}})json");
        if (!Expect(result.ok, "envelope without hash still parses"))
            return 1;
        if (!Expect(result.version == "rules-v43" && result.hash.empty(),
                    "missing metadata fields stay empty"))
            return 1;
    }

    {
        auto result = Parse(R"json({"globalLibraries":"bGliLXNpbmdsZQ==","rules":[]})json");
        if (!Expect(!result.ok, "bundle without valid rules is reported as failure"))
            return 1;
        if (!Expect(result.libSource == "lib-single", "bare globalLibraries string decodes"))
            return 1;
        if (!Expect(result.rules.empty(), "empty rules array yields no rules"))
            return 1;
    }

    {
        auto result = Parse("");
        if (!Expect(!result.ok, "empty json fails"))
            return 1;
    }

    {
        auto result = Parse("[1,2,3]");
        if (!Expect(!result.ok, "non-object top-level json fails"))
            return 1;
    }

    return 0;
}
