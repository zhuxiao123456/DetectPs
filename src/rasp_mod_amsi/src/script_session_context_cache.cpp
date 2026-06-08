#include "../include/script_session_context_cache.h"

#include <algorithm>
#include <list>
#include <mutex>
#include <unordered_map>

namespace {

constexpr std::string_view kTruncatedMarker = "\n/*<rasp_truncated>*/\n";
constexpr size_t kDefaultSuffixBytes = 1024;

struct CacheKey {
    uint32_t pid = 0;
    uint32_t tid = 0;
    uint64_t amsiSession = 0;
    std::string contentNameHash;

    bool operator==(const CacheKey& other) const
    {
        return pid == other.pid &&
               tid == other.tid &&
               amsiSession == other.amsiSession &&
               contentNameHash == other.contentNameHash;
    }
};

struct CacheKeyHash {
    size_t operator()(const CacheKey& key) const
    {
        size_t h = std::hash<uint32_t>{}(key.pid);
        h ^= std::hash<uint32_t>{}(key.tid) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint64_t>{}(key.amsiSession) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<std::string>{}(key.contentNameHash) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

CacheKey ToCacheKey(const ScriptSessionKey& key)
{
    CacheKey out;
    out.pid = key.pid;
    out.tid = key.tid;
    out.amsiSession = key.amsiSession;
    out.contentNameHash = key.contentNameHash;
    return out;
}

bool IsReliableForAggregation(const ScriptSessionKey& key)
{
    return key.confidence == SessionKeyConfidence::Strong ||
           key.confidence == SessionKeyConfidence::Medium;
}

uint64_t TtlForKey(const ScriptSessionKey& key, const SessionContextCacheConfig& config)
{
    if (key.confidence == SessionKeyConfidence::Strong)
        return config.strongTtlMs;
    if (key.confidence == SessionKeyConfidence::Medium)
        return config.mediumTtlMs;
    if (key.confidence == SessionKeyConfidence::Weak)
        return config.weakTtlMs;
    return 0;
}

SessionContextView BoundView(std::string_view input, size_t maxBytes)
{
    SessionContextView view;
    if (input.empty() || maxBytes == 0)
        return view;

    if (input.size() <= maxBytes) {
        view.body.assign(input.data(), input.size());
        return view;
    }

    view.truncated = true;
    if (maxBytes <= kTruncatedMarker.size()) {
        view.body.assign(input.data(), maxBytes);
        return view;
    }

    size_t suffixBytes = (std::min)(kDefaultSuffixBytes, maxBytes - kTruncatedMarker.size());
    size_t prefixBytes = maxBytes - suffixBytes - kTruncatedMarker.size();

    view.body.reserve(maxBytes);
    view.body.append(input.substr(0, prefixBytes));
    view.body.append(kTruncatedMarker.data(), kTruncatedMarker.size());
    view.body.append(input.substr(input.size() - suffixBytes, suffixBytes));
    return view;
}

} // namespace

struct ScriptSessionContextCache::Impl {
    struct Entry {
        std::string body;
        uint64_t lastAccessMs = 0;
        uint64_t ttlMs = 0;
        std::list<CacheKey>::iterator lruIt;
    };

    explicit Impl(SessionContextCacheConfig input)
        : config(input)
    {
        if (config.perSessionMaxBytes == 0)
            config.maxSessions = 0;
    }

    void RemoveEntry(std::unordered_map<CacheKey, Entry, CacheKeyHash>::iterator it)
    {
        cachedBytes -= it->second.body.size();
        lru.erase(it->second.lruIt);
        sessions.erase(it);
    }

    void Touch(std::unordered_map<CacheKey, Entry, CacheKeyHash>::iterator it)
    {
        lru.erase(it->second.lruIt);
        lru.push_front(it->first);
        it->second.lruIt = lru.begin();
    }

    void CleanupExpired(uint64_t nowMs)
    {
        for (auto it = sessions.begin(); it != sessions.end();) {
            const auto& entry = it->second;
            bool expired = entry.ttlMs == 0 || (nowMs - entry.lastAccessMs) > entry.ttlMs;
            if (expired) {
                auto victim = it++;
                RemoveEntry(victim);
            } else {
                ++it;
            }
        }
    }

    void EnforceLimits(const CacheKey* protectedKey)
    {
        while (sessions.size() > config.maxSessions && !lru.empty()) {
            CacheKey victim = lru.back();
            if (protectedKey && victim == *protectedKey && sessions.size() == 1)
                break;
            auto it = sessions.find(victim);
            if (it != sessions.end())
                RemoveEntry(it);
            else
                lru.pop_back();
        }

        while (cachedBytes > config.globalMaxBytes && !lru.empty()) {
            CacheKey victim = lru.back();
            if (protectedKey && victim == *protectedKey && sessions.size() == 1)
                break;
            auto it = sessions.find(victim);
            if (it != sessions.end())
                RemoveEntry(it);
            else
                lru.pop_back();
        }
    }

    SessionContextCacheConfig config;
    mutable std::mutex mutex;
    std::unordered_map<CacheKey, Entry, CacheKeyHash> sessions;
    std::list<CacheKey> lru;
    size_t cachedBytes = 0;
};

ScriptSessionContextCache::ScriptSessionContextCache(SessionContextCacheConfig config)
    : m_impl(new Impl(config))
{
}

ScriptSessionContextCache::~ScriptSessionContextCache()
{
    delete m_impl;
    m_impl = nullptr;
}

SessionContextView ScriptSessionContextCache::UpdateAndBuildView(
    const ScriptSessionKey& key,
    std::string_view normalizedChunk,
    uint64_t nowMs)
{
    if (!m_impl || normalizedChunk.empty())
        return {};

    if (!IsReliableForAggregation(key) || m_impl->config.maxSessions == 0) {
        SessionContextView view = BoundView(normalizedChunk, m_impl->config.perSessionMaxBytes);
        view.cacheBypassed = true;
        return view;
    }

    std::lock_guard<std::mutex> lock(m_impl->mutex);
    m_impl->CleanupExpired(nowMs);

    CacheKey cacheKey = ToCacheKey(key);
    auto it = m_impl->sessions.find(cacheKey);
    bool hadExisting = it != m_impl->sessions.end();

    std::string combined;
    if (hadExisting)
        combined = it->second.body;
    combined.append(normalizedChunk.data(), normalizedChunk.size());

    SessionContextView bounded = BoundView(combined, m_impl->config.perSessionMaxBytes);
    bounded.aggregated = hadExisting && !it->second.body.empty();

    if (bounded.body.size() > m_impl->config.globalMaxBytes) {
        bounded.cacheBypassed = true;
        if (hadExisting)
            m_impl->RemoveEntry(it);
        m_impl->EnforceLimits(nullptr);
        return bounded;
    }

    if (!hadExisting) {
        m_impl->lru.push_front(cacheKey);
        Impl::Entry entry;
        entry.body = bounded.body;
        entry.lastAccessMs = nowMs;
        entry.ttlMs = TtlForKey(key, m_impl->config);
        entry.lruIt = m_impl->lru.begin();
        m_impl->cachedBytes += entry.body.size();
        m_impl->sessions.emplace(cacheKey, std::move(entry));
    } else {
        m_impl->cachedBytes -= it->second.body.size();
        it->second.body = bounded.body;
        it->second.lastAccessMs = nowMs;
        it->second.ttlMs = TtlForKey(key, m_impl->config);
        m_impl->cachedBytes += it->second.body.size();
        m_impl->Touch(it);
    }

    m_impl->EnforceLimits(&cacheKey);
    return bounded;
}

void ScriptSessionContextCache::CloseSession(const ScriptSessionKey& key)
{
    if (!m_impl)
        return;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    auto it = m_impl->sessions.find(ToCacheKey(key));
    if (it != m_impl->sessions.end())
        m_impl->RemoveEntry(it);
}

void ScriptSessionContextCache::Clear()
{
    if (!m_impl)
        return;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    m_impl->sessions.clear();
    m_impl->lru.clear();
    m_impl->cachedBytes = 0;
}

size_t ScriptSessionContextCache::CachedBytes() const
{
    if (!m_impl)
        return 0;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    return m_impl->cachedBytes;
}

size_t ScriptSessionContextCache::SessionCount() const
{
    if (!m_impl)
        return 0;
    std::lock_guard<std::mutex> lock(m_impl->mutex);
    return m_impl->sessions.size();
}