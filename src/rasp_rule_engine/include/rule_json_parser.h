#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include "rasp_rule_base.h"

constexpr uint32_t kDefaultMaxScanContentBytes = 8192;
constexpr uint32_t kMinMaxScanContentBytes = 1024;
constexpr uint32_t kMaxMaxScanContentBytes = 65536;
constexpr uint32_t kDefaultTotalScanTimeoutMs = 1000;
constexpr uint32_t kMinTotalScanTimeoutMs = 50;
constexpr uint32_t kMaxTotalScanTimeoutMs = 5000;
constexpr uint32_t kDefaultAuditMaxEventsPerScan = 3;
constexpr uint32_t kMaxAuditMaxEventsPerScan = 1024;
constexpr uint32_t kDefaultScanRateLimitWindowMs = 1000;
constexpr uint32_t kMinScanRateLimitWindowMs = 100;
constexpr uint32_t kMaxScanRateLimitWindowMs = 60000;
constexpr uint32_t kDefaultScanRateLimitMaxScans = 200;
constexpr uint32_t kMinScanRateLimitMaxScans = 1;
constexpr uint32_t kMaxScanRateLimitMaxScans = 100000;
constexpr double kDefaultScanRateLimitBypassRatio = 0.8;
constexpr double kMinScanRateLimitBypassRatio = 0.0;
constexpr double kMaxScanRateLimitBypassRatio = 1.0;
constexpr uint32_t kDefaultScanContextMaxBufferedBytes = 8192;
constexpr uint32_t kMinScanContextMaxBufferedBytes = 0;
constexpr uint32_t kMaxScanContextMaxBufferedBytes = 65536;
constexpr uint32_t kDefaultScanContextTtlMs = 3000;
constexpr uint32_t kMinScanContextTtlMs = 100;
constexpr uint32_t kMaxScanContextTtlMs = 60000;
constexpr uint32_t kDefaultScanContextMaxEvalBytes = 16384;
constexpr uint32_t kMinScanContextMaxEvalBytes = 1024;
constexpr uint32_t kMaxScanContextMaxEvalBytes = 131072;

struct ScanRateLimitConfig {
    bool enabled = false;
    uint32_t windowMs = kDefaultScanRateLimitWindowMs;
    uint32_t maxScans = kDefaultScanRateLimitMaxScans;
    double bypassRatioAfterLimit = kDefaultScanRateLimitBypassRatio;
};

struct ScanContextConfig {
    bool enabled = false;
    uint32_t maxBufferedBytes = kDefaultScanContextMaxBufferedBytes;
    uint32_t ttlMs = kDefaultScanContextTtlMs;
    uint32_t maxEvalBytes = kDefaultScanContextMaxEvalBytes;
    bool clearOnMatch = true;
};

struct RuleParseResult {
    bool ok = false;
    std::vector<std::unique_ptr<RaspRuleBase>> rules;
    std::string libSource;
    std::string version;
    std::string hash;
    std::vector<std::string> trustProcessPaths;
    bool hasGlobalMode = false;
    RaspGlobalMode globalMode = RaspGlobalMode::Block;
    bool hasMaxScanContentBytes = false;
    uint32_t maxScanContentBytes = kDefaultMaxScanContentBytes;
    bool hasTotalScanTimeoutMs = false;
    uint32_t totalScanTimeoutMs = kDefaultTotalScanTimeoutMs;
    bool hasScanOptimization = false;
    uint32_t auditMaxEventsPerScan = kDefaultAuditMaxEventsPerScan;
    bool stopAfterFirstBlock = true;
    bool hasScanRateLimit = false;
    ScanRateLimitConfig scanRateLimit;
    bool hasScanContext = false;
    ScanContextConfig scanContext;
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
        bool read_double(double& out);
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
