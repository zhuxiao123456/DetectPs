#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>

struct ScanBudget
{
    uint32_t totalBudgetMs = 1000;
    uint32_t luaBudgetMs = 300;
    uint32_t maxRules = 128;
    uint32_t maxRegexCalls = 512;
    uint32_t maxRegexSubjectBytes = 64 * 1024;
    uint32_t maxLuaInstructionCount = 100000;
    uint32_t pcre2MatchLimit = 100000;
    uint32_t pcre2DepthLimit = 1000;
    uint32_t pcre2HeapLimitKiB = 1024;
};

class ScanDeadline
{
public:
    ScanDeadline() = default;

    static ScanDeadline FromNow(std::chrono::milliseconds budget)
    {
        ScanDeadline d;
        d.deadline_ = std::chrono::steady_clock::now() + budget;
        return d;
    }

    bool Expired() const
    {
        return std::chrono::steady_clock::now() >= deadline_;
    }

    uint64_t RemainingMs() const
    {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline_)
            return 0;
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline_ - now).count());
    }

private:
    std::chrono::steady_clock::time_point deadline_ =
        (std::chrono::steady_clock::time_point::max)();
};

struct ScanExecutionContext
{
    ScanBudget budget;
    ScanDeadline deadline = ScanDeadline::FromNow(std::chrono::milliseconds(budget.totalBudgetMs));
    ScanDeadline luaDeadline;
    bool luaDeadlineActive = false;

    uint32_t rulesEvaluated = 0;
    uint32_t regexCalls = 0;
    uint32_t luaInstructions = 0;
    bool timedOut = false;
    bool regexLimitHit = false;
    bool regexRuleLimitHit = false;
    bool currentRuleLimited = false;
    bool regexSubjectTruncated = false;
    bool matchedBeforeTimeout = false;
    uint32_t rulesSkippedByRegexLimit = 0;
    uint32_t regexMatchLimitHits = 0;
    uint32_t regexDepthLimitHits = 0;
    uint32_t regexHeapLimitHits = 0;
    uint32_t regexJitStackLimitHits = 0;
    std::string timeoutReason;
    std::string regexLimitType;
    std::string currentRuleLimitReason;
    std::string currentRuleLimitType;
    int currentRuleIndex = -1;
    int currentRegexCheckIndex = -1;
    int currentRegexPatternIndex = -1;
    std::string decisionAfterTimeout;

    bool MarkTimeout(const std::string& reason)
    {
        if (!timedOut) {
            timedOut = true;
            timeoutReason = reason;
        }
        return false;
    }

    bool MarkRuleLimit(const std::string& reason, const std::string& limitType)
    {
        regexLimitHit = true;
        regexRuleLimitHit = true;
        regexLimitType = limitType;
        currentRuleLimited = true;
        currentRuleLimitReason = reason;
        currentRuleLimitType = limitType;
        if (limitType == "match_limit")
            ++regexMatchLimitHits;
        else if (limitType == "depth_limit")
            ++regexDepthLimitHits;
        else if (limitType == "heap_limit")
            ++regexHeapLimitHits;
        else if (limitType == "jit_stack_limit")
            ++regexJitStackLimitHits;
        return false;
    }

    void SetRuleContext(int ruleIndex)
    {
        currentRuleIndex = ruleIndex;
        currentRegexCheckIndex = -1;
        currentRegexPatternIndex = -1;
    }

    void SetRegexCheckContext(int checkIndex)
    {
        currentRegexCheckIndex = checkIndex;
        currentRegexPatternIndex = -1;
    }

    void SetRegexPatternIndex(int index)
    {
        currentRegexPatternIndex = index;
    }

    void ClearCurrentRuleLimit()
    {
        currentRuleLimited = false;
        currentRuleLimitReason.clear();
        currentRuleLimitType.clear();
    }

    bool ShouldStopScan() const
    {
        return timedOut;
    }

    bool TryEnterRule()
    {
        if (deadline.Expired())
            return MarkTimeout("scan_timeout");
        if (rulesEvaluated >= budget.maxRules)
            return MarkTimeout("rule_budget_exceeded");
        ++rulesEvaluated;
        return true;
    }

    bool TryEnterRegexCall()
    {
        if (deadline.Expired())
            return MarkTimeout("scan_timeout");
        if (regexCalls >= budget.maxRegexCalls) {
            regexLimitHit = true;
            regexLimitType = "max_regex_calls";
            return MarkTimeout("max_regex_calls_exhausted");
        }
        ++regexCalls;
        return true;
    }

    size_t BoundedRegexSubjectLength(size_t len)
    {
        size_t limit = static_cast<size_t>(budget.maxRegexSubjectBytes);
        if (limit > 0 && len > limit) {
            regexSubjectTruncated = true;
            return limit;
        }
        return len;
    }

    bool AddLuaInstructions(uint32_t count)
    {
        uint32_t remaining = budget.maxLuaInstructionCount > luaInstructions
            ? budget.maxLuaInstructionCount - luaInstructions
            : 0;
        luaInstructions += (std::min)(count, remaining);
        if (deadline.Expired())
            return MarkTimeout("scan_timeout");
        if (luaDeadlineActive && luaDeadline.Expired())
            return MarkTimeout("lua_timeout");
        if (luaInstructions >= budget.maxLuaInstructionCount)
            return MarkTimeout("lua_timeout");
        return true;
    }
};
