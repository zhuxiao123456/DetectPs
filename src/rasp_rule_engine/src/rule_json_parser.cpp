#include "rule_json_parser.h"

#include <cctype>
#include <cstdlib>
#include <cstring>
#include <limits>

namespace {

int HexValue(char ch)
{
    if (ch >= '0' && ch <= '9')
        return ch - '0';
    if (ch >= 'a' && ch <= 'f')
        return 10 + (ch - 'a');
    if (ch >= 'A' && ch <= 'F')
        return 10 + (ch - 'A');
    return -1;
}

bool ReadJsonUnicodeEscape(const char* p, const char* end, uint32_t& value)
{
    if (end - p < 4)
        return false;
    value = 0;
    for (int i = 0; i < 4; ++i) {
        const int digit = HexValue(p[i]);
        if (digit < 0)
            return false;
        value = (value << 4) | static_cast<uint32_t>(digit);
    }
    return true;
}

void AppendUtf8(uint32_t cp, std::string& out)
{
    if (cp <= 0x7F) {
        out += static_cast<char>(cp);
    } else if (cp <= 0x7FF) {
        out += static_cast<char>(0xC0 | (cp >> 6));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else if (cp <= 0xFFFF) {
        out += static_cast<char>(0xE0 | (cp >> 12));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (cp >> 18));
        out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (cp & 0x3F));
    }
}

uint32_t ClampMaxScanContentBytes(int value)
{
    if (value < static_cast<int>(kMinMaxScanContentBytes))
        return kMinMaxScanContentBytes;
    if (value > static_cast<int>(kMaxMaxScanContentBytes))
        return kMaxMaxScanContentBytes;
    return static_cast<uint32_t>(value);
}

uint32_t ClampTotalScanTimeoutMs(int value)
{
    if (value < static_cast<int>(kMinTotalScanTimeoutMs))
        return kMinTotalScanTimeoutMs;
    if (value > static_cast<int>(kMaxTotalScanTimeoutMs))
        return kMaxTotalScanTimeoutMs;
    return static_cast<uint32_t>(value);
}

uint32_t ClampAuditMaxEventsPerScan(int value)
{
    if (value <= 0)
        return 0;
    if (value > static_cast<int>(kMaxAuditMaxEventsPerScan))
        return kMaxAuditMaxEventsPerScan;
    return static_cast<uint32_t>(value);
}

uint32_t ClampScanRateLimitWindowMs(int value)
{
    if (value < static_cast<int>(kMinScanRateLimitWindowMs))
        return kMinScanRateLimitWindowMs;
    if (value > static_cast<int>(kMaxScanRateLimitWindowMs))
        return kMaxScanRateLimitWindowMs;
    return static_cast<uint32_t>(value);
}

uint32_t ClampScanRateLimitMaxScans(int value)
{
    if (value < static_cast<int>(kMinScanRateLimitMaxScans))
        return kMinScanRateLimitMaxScans;
    if (value > static_cast<int>(kMaxScanRateLimitMaxScans))
        return kMaxScanRateLimitMaxScans;
    return static_cast<uint32_t>(value);
}

double ClampScanRateLimitBypassRatio(double value)
{
    if (value < kMinScanRateLimitBypassRatio)
        return kMinScanRateLimitBypassRatio;
    if (value > kMaxScanRateLimitBypassRatio)
        return kMaxScanRateLimitBypassRatio;
    return value;
}

uint32_t ClampScanContextMaxBufferedBytes(int value)
{
    if (value < static_cast<int>(kMinScanContextMaxBufferedBytes))
        return kMinScanContextMaxBufferedBytes;
    if (value > static_cast<int>(kMaxScanContextMaxBufferedBytes))
        return kMaxScanContextMaxBufferedBytes;
    return static_cast<uint32_t>(value);
}

uint32_t ClampScanContextTtlMs(int value)
{
    if (value < static_cast<int>(kMinScanContextTtlMs))
        return kMinScanContextTtlMs;
    if (value > static_cast<int>(kMaxScanContextTtlMs))
        return kMaxScanContextTtlMs;
    return static_cast<uint32_t>(value);
}

uint32_t ClampScanContextMaxEvalBytes(int value)
{
    if (value < static_cast<int>(kMinScanContextMaxEvalBytes))
        return kMinScanContextMaxEvalBytes;
    if (value > static_cast<int>(kMaxScanContextMaxEvalBytes))
        return kMaxScanContextMaxEvalBytes;
    return static_cast<uint32_t>(value);
}
uint32_t ClampScanContextMaxAppendBytes(int value)
{
    if (value < static_cast<int>(kMinScanContextMaxAppendBytes))
        return kMinScanContextMaxAppendBytes;
    if (value > static_cast<int>(kMaxScanContextMaxAppendBytes))
        return kMaxScanContextMaxAppendBytes;
    return static_cast<uint32_t>(value);
}

uint32_t ClampScanContextPrefixFilterBytes(int value)
{
    if (value < static_cast<int>(kMinScanContextPrefixFilterBytes))
        return kMinScanContextPrefixFilterBytes;
    if (value > static_cast<int>(kMaxScanContextPrefixFilterBytes))
        return kMaxScanContextPrefixFilterBytes;
    return static_cast<uint32_t>(value);
}

uint32_t ClampDiagnosticsScanDumpMaxBytes(int value)
{
    if (value < static_cast<int>(kMinDiagnosticsScanDumpMaxBytes))
        return kMinDiagnosticsScanDumpMaxBytes;
    if (value > static_cast<int>(kMaxDiagnosticsScanDumpMaxBytes))
        return kMaxDiagnosticsScanDumpMaxBytes;
    return static_cast<uint32_t>(value);
}

int NormalizeRuleSeverity(int value)
{
    if (value < 0 || value > 4)
        return 2;
    return value;
}

void ParseScanRateLimit(RuleJsonParser::Parser& p, RuleParseResult& result)
{
    if (!p.consume('{')) {
        p.skip_value();
        return;
    }

    result.hasScanRateLimit = true;
    while (!p.peek('}') && p.ok()) {
        std::string key;
        if (!p.read_string(key) || !p.consume(':')) {
            p.skip_value();
            break;
        }

        if (key == "enabled") {
            bool value = false;
            if (p.read_bool(value))
                result.scanRateLimit.enabled = value;
            else
                p.skip_value();
        } else if (key == "windowMs") {
            int value = 0;
            if (p.read_int(value))
                result.scanRateLimit.windowMs = ClampScanRateLimitWindowMs(value);
            else
                p.skip_value();
        } else if (key == "maxScans") {
            int value = 0;
            if (p.read_int(value))
                result.scanRateLimit.maxScans = ClampScanRateLimitMaxScans(value);
            else
                p.skip_value();
        } else if (key == "bypassRatioAfterLimit") {
            double value = kDefaultScanRateLimitBypassRatio;
            if (p.read_double(value))
                result.scanRateLimit.bypassRatioAfterLimit = ClampScanRateLimitBypassRatio(value);
            else
                p.skip_value();
        } else {
            p.skip_value();
        }

        p.consume(',');
    }
    p.consume('}');
}

void ParseScanContext(RuleJsonParser::Parser& p, RuleParseResult& result)
{
    if (!p.consume('{')) {
        p.skip_value();
        return;
    }

    result.hasScanContext = true;
    while (!p.peek('}') && p.ok()) {
        std::string key;
        if (!p.read_string(key) || !p.consume(':')) {
            p.skip_value();
            break;
        }

        if (key == "enabled") {
            bool value = false;
            if (p.read_bool(value))
                result.scanContext.enabled = value;
            else
                p.skip_value();
        } else if (key == "maxBufferedBytes") {
            int value = 0;
            if (p.read_int(value))
                result.scanContext.maxBufferedBytes = ClampScanContextMaxBufferedBytes(value);
            else
                p.skip_value();
        } else if (key == "ttlMs") {
            int value = 0;
            if (p.read_int(value))
                result.scanContext.ttlMs = ClampScanContextTtlMs(value);
            else
                p.skip_value();
        } else if (key == "maxEvalBytes") {
            int value = 0;
            if (p.read_int(value))
                result.scanContext.maxEvalBytes = ClampScanContextMaxEvalBytes(value);
            else
                p.skip_value();
        } else if (key == "clearOnMatch") {
            bool value = true;
            if (p.read_bool(value))
                result.scanContext.clearOnMatch = value;
            else
                p.skip_value();
        } else if (key == "maxAppendBytes") {
            int value = 0;
            if (p.read_int(value))
                result.scanContext.maxAppendBytes = ClampScanContextMaxAppendBytes(value);
            else
                p.skip_value();
        } else if (key == "prefixFilterBytes") {
            int value = 0;
            if (p.read_int(value))
                result.scanContext.prefixFilterBytes = ClampScanContextPrefixFilterBytes(value);
            else
                p.skip_value();
        } else {
            p.skip_value();
        }

        p.consume(',');
    }
    p.consume('}');
}

void ParseDiagnostics(RuleJsonParser::Parser& p, RuleParseResult& result)
{
    if (!p.consume('{')) {
        p.skip_value();
        return;
    }

    result.hasDiagnostics = true;
    while (!p.peek('}') && p.ok()) {
        std::string key;
        if (!p.read_string(key) || !p.consume(':')) {
            p.skip_value();
            break;
        }

        if (key == "perfLog") {
            bool value = false;
            if (p.read_bool(value))
                result.diagnostics.perfLog = value;
            else
                p.skip_value();
        } else if (key == "scanDumpLog") {
            bool value = false;
            if (p.read_bool(value))
                result.diagnostics.scanDumpLog = value;
            else
                p.skip_value();
        } else if (key == "scanDumpMaxBytes") {
            int value = 0;
            if (p.read_int(value))
                result.diagnostics.scanDumpMaxBytes = ClampDiagnosticsScanDumpMaxBytes(value);
            else
                p.skip_value();
        } else {
            p.skip_value();
        }

        p.consume(',');
    }
    p.consume('}');
}

void FinalizeScanContextConfig(RuleParseResult& result)
{
    if (result.scanContext.maxEvalBytes < result.maxScanContentBytes)
        result.scanContext.maxEvalBytes = result.maxScanContentBytes;
    if (result.scanContext.maxBufferedBytes > 0 &&
        result.scanContext.maxAppendBytes > result.scanContext.maxBufferedBytes)
        result.scanContext.maxAppendBytes = result.scanContext.maxBufferedBytes;
    if (result.scanContext.prefixFilterBytes > result.scanContext.maxAppendBytes)
        result.scanContext.prefixFilterBytes = result.scanContext.maxAppendBytes;
}

void ParseScanOptimization(RuleJsonParser::Parser& p, RuleParseResult& result)
{
    if (!p.consume('{')) {
        p.skip_value();
        return;
    }

    result.hasScanOptimization = true;
    while (!p.peek('}') && p.ok()) {
        std::string key;
        if (!p.read_string(key) || !p.consume(':')) {
            p.skip_value();
            break;
        }

        if (key == "auditMaxEventsPerScan") {
            int value = 0;
            if (p.read_int(value))
                result.auditMaxEventsPerScan = ClampAuditMaxEventsPerScan(value);
            else
                p.skip_value();
        } else if (key == "stopAfterFirstBlock") {
            bool value = true;
            if (p.read_bool(value))
                result.stopAfterFirstBlock = value;
            else
                p.skip_value();
        } else {
            p.skip_value();
        }

        p.consume(',');
    }
    p.consume('}');
}

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
            else if (rkey == "severity") {
                int severity = 2;
                if (p.read_int(severity))
                    rule.severity = NormalizeRuleSeverity(severity);
                else
                    p.skip_value();
            }
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
        } else if (key == "trust_process") {
            if (!p.read_string_array(result.trustProcessPaths))
                p.skip_value();
        } else if (key == "globalMode") {
            std::string mode;
            if (p.read_string(mode)) {
                if (mode == "block") {
                    result.globalMode = RaspGlobalMode::Block;
                    result.hasGlobalMode = true;
                } else if (mode == "audit") {
                    result.globalMode = RaspGlobalMode::Audit;
                    result.hasGlobalMode = true;
                }
            } else {
                p.skip_value();
            }
        } else if (key == "maxScanContentBytes") {
            int value = 0;
            if (p.read_int(value)) {
                result.maxScanContentBytes = ClampMaxScanContentBytes(value);
                result.hasMaxScanContentBytes = true;
            } else {
                p.skip_value();
            }
        } else if (key == "totalScanTimeoutMs") {
            int value = 0;
            if (p.read_int(value)) {
                result.totalScanTimeoutMs = ClampTotalScanTimeoutMs(value);
                result.hasTotalScanTimeoutMs = true;
            } else {
                p.skip_value();
            }
        } else if (key == "scanOptimization") {
            ParseScanOptimization(p, result);
        } else if (key == "scanRateLimit") {
            ParseScanRateLimit(p, result);
        } else if (key == "scanContext") {
            ParseScanContext(p, result);
        } else if (key == "diagnostics") {
            ParseDiagnostics(p, result);
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
            if (p >= end)
                return false;

            switch (*p) {
            case '"': out += '"'; ++p; break;
            case '\\': out += '\\'; ++p; break;
            case '/': out += '/'; ++p; break;
            case 'b': out += '\b'; ++p; break;
            case 'f': out += '\f'; ++p; break;
            case 'n': out += '\n'; ++p; break;
            case 'r': out += '\r'; ++p; break;
            case 't': out += '\t'; ++p; break;
            case 'u': {
                ++p;
                uint32_t cp = 0;
                if (!ReadJsonUnicodeEscape(p, end, cp))
                    return false;
                p += 4;

                if (cp >= 0xD800 && cp <= 0xDBFF) {
                    if (end - p < 6 || p[0] != '\\' || p[1] != 'u')
                        return false;
                    uint32_t low = 0;
                    if (!ReadJsonUnicodeEscape(p + 2, end, low) ||
                        low < 0xDC00 || low > 0xDFFF)
                        return false;
                    p += 6;
                    cp = 0x10000 + (((cp - 0xD800) << 10) | (low - 0xDC00));
                } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
                    return false;
                }

                AppendUtf8(cp, out);
                break;
            }
            default:
                return false;
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
    const int limit = std::numeric_limits<int>::min();
    const int cutoff = limit / 10;
    const int cutlim = neg ? 8 : 7;
    int value = 0;
    bool saturated = false;
    while (ok() && std::isdigit(static_cast<unsigned char>(*p))) {
        const int digit = *p++ - '0';
        if (!saturated) {
            if (value < cutoff || (value == cutoff && digit > cutlim)) {
                value = limit;
                saturated = true;
            } else {
                value = value * 10 - digit;
            }
        }
    }
    out = neg ? value : (value == std::numeric_limits<int>::min()
        ? std::numeric_limits<int>::max()
        : -value);
    return true;
}

bool RuleJsonParser::Parser::read_double(double& out)
{
    skip_ws();
    if (!ok())
        return false;

    char* parsedEnd = nullptr;
    out = std::strtod(p, &parsedEnd);
    if (parsedEnd == p)
        return false;
    p = parsedEnd;
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
        } else if (key == "trust_process") {
            if (!p.read_string_array(result.trustProcessPaths))
                p.skip_value();
        } else if (key == "globalMode") {
            std::string mode;
            if (p.read_string(mode)) {
                if (mode == "block") {
                    result.globalMode = RaspGlobalMode::Block;
                    result.hasGlobalMode = true;
                } else if (mode == "audit") {
                    result.globalMode = RaspGlobalMode::Audit;
                    result.hasGlobalMode = true;
                }
            } else {
                p.skip_value();
            }
        } else if (key == "maxScanContentBytes") {
            int value = 0;
            if (p.read_int(value)) {
                result.maxScanContentBytes = ClampMaxScanContentBytes(value);
                result.hasMaxScanContentBytes = true;
            } else {
                p.skip_value();
            }
        } else if (key == "totalScanTimeoutMs") {
            int value = 0;
            if (p.read_int(value)) {
                result.totalScanTimeoutMs = ClampTotalScanTimeoutMs(value);
                result.hasTotalScanTimeoutMs = true;
            } else {
                p.skip_value();
            }
        } else if (key == "scanOptimization") {
            ParseScanOptimization(p, result);
        } else if (key == "scanRateLimit") {
            ParseScanRateLimit(p, result);
        } else if (key == "scanContext") {
            ParseScanContext(p, result);
        } else if (key == "diagnostics") {
            ParseDiagnostics(p, result);
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
    FinalizeScanContextConfig(result);
    return result;
}
