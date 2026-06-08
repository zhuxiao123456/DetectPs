#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>

struct NormalizedScriptInput
{
    std::string normalized;
    size_t rawLen = 0;
    size_t normalizedLen = 0;
    bool truncated = false;
    bool hadNullBytes = false;
    bool decodedBase64 = false;
    bool decodedUtf16Le = false;
    std::string sampleHash;
    std::string normalizationReason;
};

class ScriptInputNormalizer
{
public:
    static constexpr size_t kMaxNormalizedBodyBytes = 4096;
    static constexpr size_t kPrefixBytes = 3072;
    static constexpr size_t kSuffixBytes = 1024;
    static constexpr size_t kMaxEncodedCommandTokenBytes = 8192;

    static const char* TruncatedMarker();
    NormalizedScriptInput Normalize(const char* sample, ULONG sampleLen) const;
    NormalizedScriptInput Normalize(const char* sample,
                                    ULONG sampleLen,
                                    size_t maxNormalizedBodyBytes) const;
};
