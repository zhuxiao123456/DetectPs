#include "rule_json_parser.h"

#include <cctype>
#include <cstring>

namespace {

bool Base64Decode(const std::string& input, std::string& output)
{
    static const int kDecodeTable[128] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1
    };

    output.clear();
    output.reserve((input.size() / 4) * 3 + 3);

    int val = 0;
    int valb = -8;
    for (unsigned char c : input) {
        if (c == '=' || c == '\r' || c == '\n' || c == ' ')
            continue;
        if (c > 127)
            return false;
        int d = kDecodeTable[c];
        if (d < 0)
            return false;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            output += static_cast<char>((val >> valb) & 0xFF);
            valb -= 8;
        }
    }

    return true;
}

void ParseGlobalLibraries(RuleJsonParser::Parser& p, RuleParseResult& result)
{
    p.skip_ws();
    if (p.peek('[')) {
        std::vector<std::string> items;
        p.read_string_array(items);
        for (const auto& b64 : items) {
            std::string decoded;
            if (Base64Decode(b64, decoded))
                result.libSource += decoded + "\n";
        }
        return;
    }

    std::string b64;
    p.read_string(b64);
    std::string decoded;
    if (!b64.empty() && Base64Decode(b64, decoded))
        result.libSource = decoded;
}

bool ParseRulesArray(RuleJsonParser::Parser& p,
                     RuleParseResult& result,
                     const IRuleObjectFactory& factory,
                     IRuleExtensionParser& extensionParser)
{
    if (!p.consume('[')) {
        p.skip_value();
        return true;
    }

    while (!p.peek(']') && p.ok()) {
        if (!p.peek('{')) {
            p.skip_value();
            p.consume(',');
            continue;
        }

        std::unique_ptr<RaspRuleBase> rulePtr(factory.CreateRule());
        if (!rulePtr) {
            result.error = "factory_returned_null";
            return false;
        }
        RaspRuleBase& rule = *rulePtr;

        if (!p.consume('{')) {
            p.consume(',');
            continue;
        }

        while (!p.peek('}') && p.ok()) {
            std::string rkey;
            if (!p.read_string(rkey) || !p.consume(':'))
                break;

            if (rkey == "id")
                p.read_string(rule.id);
            else if (rkey == "sensor")
                p.read_string(rule.sensor);
            else if (rkey == "enabled")
                p.read_bool(rule.enabled);
            else if (rkey == "description")
                p.read_string(rule.description);
            else if (rkey == "severity")
                p.read_string(rule.severity);
            else if (rkey == "scriptBodyBase64")
                p.read_string(rule.scriptBodyBase64);
            else if (rkey == "scriptEncoding")
                p.read_string(rule.scriptEncoding);
            else if (rkey == "scriptEval")
                p.read_string(rule.scriptEval);
            else if (rkey == "confidence")
                p.read_int(rule.confidence);
            else if (rkey == "mode") {
                std::string m;
                p.read_string(m);
                if (m == "block")
                    rule.mode = RaspRuleMode::Block;
                else if (m == "off")
                    rule.mode = RaspRuleMode::Off;
                else
                    rule.mode = RaspRuleMode::Audit;
            } else if (rkey == "scriptTimeoutMs") {
                int ms = 0;
                p.read_int(ms);
                rule.scriptTimeoutInstructions = ms * 50000;
                if (rule.scriptTimeoutInstructions <= 0)
                    rule.scriptTimeoutInstructions = 500000;
            } else {
                extensionParser.ParseRuleExtension(rkey, &p, rule);
            }

            p.consume(',');
        }
        p.consume('}');

        if (!rule.id.empty())
            result.rules.push_back(std::move(rulePtr));

        p.consume(',');
    }
    p.consume(']');
    return true;
}

bool ParseBundleObject(RuleJsonParser::Parser& p,
                       RuleParseResult& result,
                       const IRuleObjectFactory& factory,
                       IRuleExtensionParser& extensionParser)
{
    if (!p.consume('{')) {
        p.skip_value();
        return true;
    }

    while (!p.peek('}') && p.ok()) {
        std::string key;
        if (!p.read_string(key) || !p.consume(':')) {
            result.error = "invalid_bundle_field";
            break;
        }

        if (key == "rules") {
            if (!ParseRulesArray(p, result, factory, extensionParser))
                return false;
        } else {
            p.skip_value();
        }

        p.consume(',');
    }
    p.consume('}');
    return true;
}

} // namespace

void RuleJsonParser::Parser::skip_ws()
{
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n'))
        ++p;
}

bool RuleJsonParser::Parser::peek(char c)
{
    skip_ws();
    return ok() && *p == c;
}

bool RuleJsonParser::Parser::consume(char c)
{
    skip_ws();
    if (ok() && *p == c) {
        ++p;
        return true;
    }
    return false;
}

bool RuleJsonParser::Parser::read_string(std::string& out)
{
    out.clear();
    if (!consume('"'))
        return false;
    while (p < end && *p != '"') {
        if (*p == '\\') {
            ++p;
            if (p < end) {
                out += *p;
                ++p;
            }
        } else {
            out += *p++;
        }
    }
    return consume('"');
}

bool RuleJsonParser::Parser::read_bool(bool& out)
{
    skip_ws();
    if (p + 4 <= end && std::strncmp(p, "true", 4) == 0) {
        out = true;
        p += 4;
        return true;
    }
    if (p + 5 <= end && std::strncmp(p, "false", 5) == 0) {
        out = false;
        p += 5;
        return true;
    }
    return false;
}

bool RuleJsonParser::Parser::read_int(int& out)
{
    skip_ws();
    if (!ok())
        return false;
    bool neg = false;
    if (*p == '-') {
        neg = true;
        ++p;
    }
    if (!ok() || !std::isdigit(static_cast<unsigned char>(*p)))
        return false;
    out = 0;
    while (ok() && std::isdigit(static_cast<unsigned char>(*p)))
        out = out * 10 + (*p++ - '0');
    if (neg)
        out = -out;
    return true;
}

bool RuleJsonParser::Parser::read_string_array(std::vector<std::string>& out)
{
    if (!consume('['))
        return false;
    out.clear();
    while (!peek(']')) {
        std::string s;
        if (!read_string(s)) {
            skip_value();
            break;
        }
        out.push_back(s);
        consume(',');
    }
    return consume(']');
}

bool RuleJsonParser::Parser::read_regex_check_array(std::vector<RegexCheck>& out)
{
    if (!consume('['))
        return false;
    out.clear();
    while (!peek(']') && ok()) {
        if (!consume('{')) {
            skip_value();
            consume(',');
            continue;
        }
        RegexCheck chk;
        while (!peek('}') && ok()) {
            std::string key;
            if (!read_string(key) || !consume(':'))
                break;
            if (key == "id")
                read_string(chk.id);
            else if (key == "field")
                read_string(chk.field);
            else if (key == "patterns")
                read_string_array(chk.patterns);
            else
                skip_value();
            consume(',');
        }
        consume('}');
        if (!chk.id.empty() && !chk.patterns.empty())
            out.push_back(std::move(chk));
        consume(',');
    }
    return consume(']');
}

void RuleJsonParser::Parser::skip_value()
{
    skip_ws();
    if (!ok())
        return;
    if (*p == '"') {
        std::string d;
        read_string(d);
        return;
    }
    if (*p == '{') {
        skip_object();
        return;
    }
    if (*p == '[') {
        skip_array();
        return;
    }
    while (ok() && *p != ',' && *p != '}' && *p != ']' &&
           *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n')
        ++p;
}

void RuleJsonParser::Parser::skip_array()
{
    consume('[');
    while (!peek(']') && ok()) {
        skip_value();
        consume(',');
    }
    consume(']');
}

void RuleJsonParser::Parser::skip_object()
{
    consume('{');
    while (!peek('}') && ok()) {
        std::string key;
        read_string(key);
        consume(':');
        skip_value();
        consume(',');
    }
    consume('}');
}

RuleParseResult RuleJsonParser::Parse(std::string_view json,
                                      const IRuleObjectFactory& factory,
                                      IRuleExtensionParser& extensionParser) const
{
    RuleParseResult result;
    if (json.empty()) {
        result.error = "empty_json";
        return result;
    }

    Parser p(json.data(), json.size());
    if (!p.consume('{')) {
        result.error = "top_level_not_object";
        return result;
    }

    while (!p.peek('}') && p.ok()) {
        std::string key;
        if (!p.read_string(key) || !p.consume(':')) {
            result.error = "invalid_top_level_field";
            break;
        }

        if (key == "version") {
            if (!p.read_string(result.version))
                p.skip_value();
        } else if (key == "hash") {
            if (!p.read_string(result.hash))
                p.skip_value();
        } else if (key == "globalLibrariesBase64" || key == "globalLibraries") {
            ParseGlobalLibraries(p, result);
        } else if (key == "rules") {
            if (!ParseRulesArray(p, result, factory, extensionParser))
                return result;
        } else if (key == "bundle") {
            if (!ParseBundleObject(p, result, factory, extensionParser))
                return result;
        } else {
            p.skip_value();
        }

        p.consume(',');
    }

    result.ok = !result.rules.empty();
    if (!result.ok && result.error.empty())
        result.error = "no_valid_rules";
    return result;
}
