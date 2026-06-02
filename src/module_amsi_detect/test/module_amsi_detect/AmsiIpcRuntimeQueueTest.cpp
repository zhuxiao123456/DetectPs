#include "gtest/gtest.h"
#include "AmsiIpcRuntimeQueue.h"

#include <atomic>
#include <chrono>
#include <thread>

using Engine::BoundedPayloadQueue;
using Engine::RuntimePayloadEnvelope;

class BoundedPayloadQueueTest : public ::testing::Test {
protected:
    void SetUp() override {}
    void TearDown() override {}

    RuntimePayloadEnvelope MakeEnvelope(Engine::AmsiIpcPayloadKind kind, const std::string &json) {
        RuntimePayloadEnvelope e;
        e.kind = kind;
        e.rawJson = json;
        e.receivedTimeMs = 0;
        return e;
    }
};

TEST_F(BoundedPayloadQueueTest, DefaultConstructor_HasZeroCapacity) {
    BoundedPayloadQueue q;
    EXPECT_EQ(q.Size(), 0u);
    EXPECT_EQ(q.Bytes(), 0u);
}

TEST_F(BoundedPayloadQueueTest, ParameterizedConstructor_SetsCapacity) {
    BoundedPayloadQueue q(10, 1024);
    EXPECT_EQ(q.Size(), 0u);
    EXPECT_EQ(q.Bytes(), 0u);
}

TEST_F(BoundedPayloadQueueTest, PushAndPop_SingleItem) {
    BoundedPayloadQueue q(10, 1024);
    auto env = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, R"({"test":"data"})");
    ASSERT_TRUE(q.Push(std::move(env), 0, false));

    RuntimePayloadEnvelope out;
    ASSERT_TRUE(q.Pop(out));
    EXPECT_EQ(out.kind, Engine::AmsiIpcPayloadKind::Detection);
    EXPECT_EQ(out.rawJson, R"({"test":"data"})");
}

TEST_F(BoundedPayloadQueueTest, PushUpdatesSizeAndBytes) {
    BoundedPayloadQueue q(10, 1024);
    auto env = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "hello");
    ASSERT_TRUE(q.Push(std::move(env), 0, false));
    EXPECT_EQ(q.Size(), 1u);
    EXPECT_EQ(q.Bytes(), 5u);
}

TEST_F(BoundedPayloadQueueTest, PopUpdatesSizeAndBytes) {
    BoundedPayloadQueue q(10, 1024);
    auto env = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "hello");
    q.Push(std::move(env), 0, false);
    RuntimePayloadEnvelope out;
    q.Pop(out);
    EXPECT_EQ(q.Size(), 0u);
    EXPECT_EQ(q.Bytes(), 0u);
}

TEST_F(BoundedPayloadQueueTest, PushFailsOnZeroCapacity) {
    BoundedPayloadQueue q;
    auto env = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "data");
    EXPECT_FALSE(q.Push(std::move(env), 0, false));
}

TEST_F(BoundedPayloadQueueTest, TryPush_SucceedsWhenSpaceAvailable) {
    BoundedPayloadQueue q(10, 1024);
    auto env = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "ok");
    EXPECT_TRUE(q.TryPush(std::move(env)));
}

TEST_F(BoundedPayloadQueueTest, TryPush_FailsWhenFull) {
    BoundedPayloadQueue q(1, 1024);
    auto env1 = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "first");
    ASSERT_TRUE(q.TryPush(std::move(env1)));
    auto env2 = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "second");
    EXPECT_FALSE(q.TryPush(std::move(env2)));
}

TEST_F(BoundedPayloadQueueTest, PushFailsWhenOversized) {
    BoundedPayloadQueue q(10, 5);
    auto env = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "toolarge_data");
    EXPECT_FALSE(q.Push(std::move(env), 0, false));
}

TEST_F(BoundedPayloadQueueTest, PushFailsWhenTotalBytesWouldExceedLimit) {
    BoundedPayloadQueue q(10, 8);
    auto env1 = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "12345");
    ASSERT_TRUE(q.Push(std::move(env1), 0, false));

    auto env2 = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "6789");
    EXPECT_FALSE(q.Push(std::move(env2), 0, false));
    EXPECT_EQ(q.Size(), 1u);
    EXPECT_EQ(q.Bytes(), 5u);
}

TEST_F(BoundedPayloadQueueTest, PushWaitWhenFull_TimesOut) {
    BoundedPayloadQueue q(1, 1024);
    auto env1 = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "first");
    ASSERT_TRUE(q.Push(std::move(env1), 0, false));

    auto env2 = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "second");
    EXPECT_FALSE(q.Push(std::move(env2), 20, true));
    EXPECT_EQ(q.Size(), 1u);
}

TEST_F(BoundedPayloadQueueTest, PushWaitWhenFull_SucceedsAfterPopFreesSpace) {
    BoundedPayloadQueue q(1, 1024);
    auto env1 = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "first");
    ASSERT_TRUE(q.Push(std::move(env1), 0, false));

    std::atomic<bool> pushResult{false};
    std::thread producer([&]() {
        auto env2 = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "second");
        pushResult.store(q.Push(std::move(env2), 1000, true));
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    RuntimePayloadEnvelope out;
    ASSERT_TRUE(q.Pop(out));
    producer.join();

    EXPECT_TRUE(pushResult.load());
    ASSERT_TRUE(q.Pop(out));
    EXPECT_EQ(out.rawJson, "second");
}

TEST_F(BoundedPayloadQueueTest, StopWakesProducerWaitingForSpace) {
    BoundedPayloadQueue q(1, 1024);
    auto env1 = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "first");
    ASSERT_TRUE(q.Push(std::move(env1), 0, false));

    std::atomic<bool> pushResult{true};
    std::thread producer([&]() {
        auto env2 = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "second");
        pushResult.store(q.Push(std::move(env2), 1000, true));
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    q.Stop();
    producer.join();

    EXPECT_FALSE(pushResult.load());
}

TEST_F(BoundedPayloadQueueTest, StopCausesPushToFail) {
    BoundedPayloadQueue q(10, 1024);
    q.Stop();
    auto env = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "data");
    EXPECT_FALSE(q.Push(std::move(env), 0, false));
}

TEST_F(BoundedPayloadQueueTest, StopCausesPopToReturnFalse) {
    BoundedPayloadQueue q(10, 1024);
    q.Stop();
    RuntimePayloadEnvelope out;
    EXPECT_FALSE(q.Pop(out));
}

TEST_F(BoundedPayloadQueueTest, StopAndDrop_ClearsData) {
    BoundedPayloadQueue q(10, 1024);
    auto env = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "data");
    q.Push(std::move(env), 0, false);
    EXPECT_EQ(q.Size(), 1u);

    q.StopAndDrop();
    EXPECT_EQ(q.Size(), 0u);
    EXPECT_EQ(q.Bytes(), 0u);
}

TEST_F(BoundedPayloadQueueTest, Clear_RemovesDataWithoutStopping) {
    BoundedPayloadQueue q(10, 1024);
    auto env = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "data");
    q.Push(std::move(env), 0, false);
    q.Clear();
    EXPECT_EQ(q.Size(), 0u);
    EXPECT_EQ(q.Bytes(), 0u);

    auto env2 = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "data2");
    EXPECT_TRUE(q.Push(std::move(env2), 0, false));
}

TEST_F(BoundedPayloadQueueTest, ClearWakesProducerWaitingForSpace) {
    BoundedPayloadQueue q(1, 1024);
    auto env1 = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "first");
    ASSERT_TRUE(q.Push(std::move(env1), 0, false));

    std::atomic<bool> pushResult{false};
    std::thread producer([&]() {
        auto env2 = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "second");
        pushResult.store(q.Push(std::move(env2), 1000, true));
    });

    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    q.Clear();
    producer.join();

    EXPECT_TRUE(pushResult.load());
    EXPECT_EQ(q.Size(), 1u);
    EXPECT_EQ(q.Bytes(), 6u);
}

TEST_F(BoundedPayloadQueueTest, Reset_ReinitializesQueue) {
    BoundedPayloadQueue q;
    q.Reset(10, 1024);
    auto env = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "data");
    EXPECT_TRUE(q.Push(std::move(env), 0, false));
    EXPECT_EQ(q.Size(), 1u);
}

TEST_F(BoundedPayloadQueueTest, Reset_ClearsExistingData) {
    BoundedPayloadQueue q(10, 1024);
    auto env = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "data");
    q.Push(std::move(env), 0, false);
    q.Reset(10, 1024);
    EXPECT_EQ(q.Size(), 0u);
    EXPECT_EQ(q.Bytes(), 0u);
}

TEST_F(BoundedPayloadQueueTest, Reset_RestoresStoppedQueue) {
    BoundedPayloadQueue q(10, 1024);
    q.Stop();
    auto env = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "data");
    EXPECT_FALSE(q.Push(std::move(env), 0, false));

    q.Reset(10, 1024);
    auto env2 = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "data2");
    EXPECT_TRUE(q.Push(std::move(env2), 0, false));
}

TEST_F(BoundedPayloadQueueTest, MultiplePushAndPop) {
    BoundedPayloadQueue q(10, 1024);
    for (int i = 0; i < 5; ++i) {
        auto env = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "item" + std::to_string(i));
        ASSERT_TRUE(q.Push(std::move(env), 0, false));
    }
    EXPECT_EQ(q.Size(), 5u);

    for (int i = 0; i < 5; ++i) {
        RuntimePayloadEnvelope out;
        ASSERT_TRUE(q.Pop(out));
        EXPECT_EQ(out.rawJson, "item" + std::to_string(i));
    }
    EXPECT_EQ(q.Size(), 0u);
}

TEST_F(BoundedPayloadQueueTest, PopReturnsRemainingItemsAfterStop) {
    BoundedPayloadQueue q(10, 1024);
    auto env = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "data");
    q.Push(std::move(env), 0, false);
    q.Stop();

    RuntimePayloadEnvelope out;
    EXPECT_TRUE(q.Pop(out));
    EXPECT_EQ(out.rawJson, "data");
    EXPECT_FALSE(q.Pop(out));
}

TEST_F(BoundedPayloadQueueTest, ConcurrentPushAndPop) {
    BoundedPayloadQueue q(100, 65536);
    const int itemCount = 50;
    std::atomic<int> popCount{0};

    std::thread consumer([&]() {
        RuntimePayloadEnvelope out;
        while (q.Pop(out)) {
            popCount.fetch_add(1);
        }
    });

    for (int i = 0; i < itemCount; ++i) {
        auto env = MakeEnvelope(Engine::AmsiIpcPayloadKind::Detection, "item" + std::to_string(i));
        q.Push(std::move(env), 100, true);
    }

    q.Stop();
    consumer.join();
    EXPECT_EQ(popCount.load(), itemCount);
}
