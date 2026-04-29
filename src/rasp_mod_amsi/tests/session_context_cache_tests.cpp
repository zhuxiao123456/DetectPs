#include "../include/script_session_context_cache.h"

#include <atomic>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition)
        std::cerr << "FAIL: " << message << "\n";
    return condition;
}

ScriptSessionKey Key(uint32_t pid,
                     uint32_t tid,
                     uint64_t session,
                     const char* content,
                     SessionKeyConfidence confidence = SessionKeyConfidence::Strong)
{
    ScriptSessionKey key;
    key.pid = pid;
    key.tid = tid;
    key.amsiSession = session;
    key.contentNameHash = content;
    key.confidence = confidence;
    return key;
}

std::string Repeat(char ch, size_t count)
{
    return std::string(count, ch);
}

} // namespace

int main()
{
    {
        ScriptSessionContextCache cache;
        auto view = cache.UpdateAndBuildView(Key(1, 2, 3, "a"), "I", 1000);
        if (!Expect(view.body == "I", "single chunk is visible"))
            return 1;
        if (!Expect(!view.aggregated, "first chunk is not aggregated"))
            return 1;
        view = cache.UpdateAndBuildView(Key(1, 2, 3, "a"), "EX", 1001);
        if (!Expect(view.body.find("IEX") != std::string::npos,
                    "chunks are appended without delimiter"))
            return 1;
        if (!Expect(view.body.find("I EX") == std::string::npos,
                    "chunks do not insert spaces"))
            return 1;
    }

    {
        ScriptSessionContextCache cache;
        auto view = cache.UpdateAndBuildView(Key(1, 2, 3, "long"),
                                             Repeat('A', 5000),
                                             1000);
        if (!Expect(view.body.size() <= 4096, "view is capped at 4096 bytes"))
            return 1;
        if (!Expect(view.truncated, "oversized current chunk is marked truncated"))
            return 1;
        if (!Expect(view.body.find("/*<rasp_truncated>*/") != std::string::npos,
                    "truncated view contains marker"))
            return 1;
    }

    {
        ScriptSessionContextCache cache;
        auto weak = cache.UpdateAndBuildView(
            Key(1, 2, 3, "weak", SessionKeyConfidence::Weak), "old", 1000);
        auto weak2 = cache.UpdateAndBuildView(
            Key(1, 2, 3, "weak", SessionKeyConfidence::Weak), "new", 1001);
        if (!Expect(weak.body == "old" && weak.cacheBypassed,
                    "weak key returns current chunk and bypasses cache"))
            return 1;
        if (!Expect(weak2.body == "new" && weak2.cacheBypassed,
                    "weak key does not aggregate"))
            return 1;

        auto none = cache.UpdateAndBuildView(
            Key(1, 2, 3, "none", SessionKeyConfidence::None), "chunk", 1002);
        if (!Expect(none.body == "chunk" && none.cacheBypassed,
                    "none key returns current chunk and bypasses cache"))
            return 1;
    }

    {
        SessionContextCacheConfig config;
        config.strongTtlMs = 10;
        ScriptSessionContextCache cache(config);
        cache.UpdateAndBuildView(Key(1, 2, 3, "ttl"), "old", 1000);
        auto view = cache.UpdateAndBuildView(Key(1, 2, 3, "ttl"), "new", 1011);
        if (!Expect(view.body == "new", "expired session returns current chunk only"))
            return 1;
    }

    {
        SessionContextCacheConfig config;
        config.maxSessions = 1;
        ScriptSessionContextCache cache(config);
        cache.UpdateAndBuildView(Key(1, 1, 1, "a"), "old", 1000);
        cache.UpdateAndBuildView(Key(2, 1, 1, "b"), "other", 1001);
        auto view = cache.UpdateAndBuildView(Key(1, 1, 1, "a"), "new", 1002);
        if (!Expect(view.body == "new", "LRU-evicted session restarts from current chunk"))
            return 1;
    }

    {
        ScriptSessionContextCache cache;
        cache.UpdateAndBuildView(Key(1, 2, 3, "a"), "left", 1000);
        auto otherName = cache.UpdateAndBuildView(Key(1, 2, 3, "b"), "right", 1001);
        if (!Expect(otherName.body == "right", "different contentNameHash is isolated"))
            return 1;
        auto otherPid = cache.UpdateAndBuildView(Key(2, 2, 3, "a"), "pid", 1002);
        if (!Expect(otherPid.body == "pid", "different pid is isolated"))
            return 1;
    }

    {
        ScriptSessionContextCache cache;
        auto key = Key(1, 2, 3, "close");
        cache.UpdateAndBuildView(key, "old", 1000);
        if (!Expect(cache.CachedBytes() == 3, "cached bytes tracks actual body"))
            return 1;
        cache.UpdateAndBuildView(key, "new", 1001);
        if (!Expect(cache.CachedBytes() == 6, "cached bytes is not double-counted"))
            return 1;
        cache.CloseSession(key);
        if (!Expect(cache.CachedBytes() == 0 && cache.SessionCount() == 0,
                    "CloseSession releases cached memory"))
            return 1;
        auto view = cache.UpdateAndBuildView(key, "again", 1002);
        if (!Expect(view.body == "again", "closed session restarts from current chunk"))
            return 1;
        cache.Clear();
        if (!Expect(cache.CachedBytes() == 0 && cache.SessionCount() == 0,
                    "Clear releases all cached memory"))
            return 1;
    }

    {
        SessionContextCacheConfig config;
        config.globalMaxBytes = 8;
        ScriptSessionContextCache cache(config);
        cache.UpdateAndBuildView(Key(1, 1, 1, "a"), "1234", 1000);
        cache.UpdateAndBuildView(Key(2, 1, 1, "b"), "5678", 1001);
        auto view = cache.UpdateAndBuildView(Key(3, 1, 1, "c"), "abcd", 1002);
        if (!Expect(view.body == "abcd", "global pressure keeps current chunk visible"))
            return 1;
        if (!Expect(cache.CachedBytes() <= 8, "global memory cap is enforced"))
            return 1;
    }

    {
        ScriptSessionContextCache cache;
        auto empty = cache.UpdateAndBuildView(Key(1, 1, 1, "empty"), "", 1000);
        if (!Expect(empty.body.empty(), "empty chunk is allowed"))
            return 1;
    }

    {
        ScriptSessionContextCache cache;
        std::atomic<bool> failed{false};
        auto workerSame = [&]() {
            for (int i = 0; i < 200; ++i) {
                auto view = cache.UpdateAndBuildView(Key(9, 9, 9, "same"), "x", 1000 + i);
                if (view.body.size() > 4096)
                    failed.store(true);
            }
        };
        std::thread t1(workerSame);
        std::thread t2(workerSame);
        t1.join();
        t2.join();
        if (!Expect(!failed.load(), "concurrent same-key updates stay bounded"))
            return 1;
    }

    {
        ScriptSessionContextCache cache;
        std::atomic<bool> failed{false};
        auto workerDifferent = [&](uint32_t pid) {
            for (int i = 0; i < 100; ++i) {
                auto view = cache.UpdateAndBuildView(Key(pid, 1, 1, "different"), "y", 2000 + i);
                if (view.body.size() > 4096)
                    failed.store(true);
            }
        };
        std::thread t1(workerDifferent, 10);
        std::thread t2(workerDifferent, 11);
        t1.join();
        t2.join();
        if (!Expect(!failed.load(), "concurrent different-key updates stay bounded"))
            return 1;
    }

    return 0;
}
