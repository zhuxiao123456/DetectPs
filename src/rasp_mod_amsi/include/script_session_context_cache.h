#pragma once

// Dormant / experimental component.
// Not wired into the production AMSI scan path in the current release.
// Keep tests for future research; do not include this header from
// amsi_rule_engine.h unless session aggregation is explicitly re-enabled.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

enum class SessionKeyConfidence {
    Strong,
    Medium,
    Weak,
    None
};

struct ScriptSessionKey {
    uint32_t pid = 0;
    uint32_t tid = 0;
    uint64_t amsiSession = 0;
    std::string contentNameHash;
    SessionKeyConfidence confidence = SessionKeyConfidence::None;
};

struct SessionContextView {
    std::string body;
    bool aggregated = false;
    bool truncated = false;
    bool cacheBypassed = false;
};

struct SessionContextCacheConfig {
    size_t perSessionMaxBytes = 4096;
    size_t globalMaxBytes = 1024 * 1024;
    size_t maxSessions = 1024;
    uint64_t strongTtlMs = 60000;
    uint64_t mediumTtlMs = 30000;
    uint64_t weakTtlMs = 5000;
};

class ScriptSessionContextCache {
public:
    explicit ScriptSessionContextCache(SessionContextCacheConfig config = {});
    ~ScriptSessionContextCache();

    ScriptSessionContextCache(const ScriptSessionContextCache&) = delete;
    ScriptSessionContextCache& operator=(const ScriptSessionContextCache&) = delete;

    SessionContextView UpdateAndBuildView(
        const ScriptSessionKey& key,
        std::string_view normalizedChunk,
        uint64_t nowMs);

    void CloseSession(const ScriptSessionKey& key);
    void Clear();

    size_t CachedBytes() const;
    size_t SessionCount() const;

private:
    struct Impl;
    Impl* m_impl;
};
