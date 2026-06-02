# AMSI IPC DrainAckQueue 轻量设计方案

## 1. 背景

当前 `AmsiIpcRuntime` 已能从 event pipe 中识别：

```json
{"cat":"drain-ack"}
```

但当前实现只做计数：

```cpp
drainAckReceived.fetch_add(1);
```

这可以支持“收到多少条 drain-ack”的粗略统计，但无法像 `amsi_staging_watcher.cpp::WaitForDrainAck()` 那样保存每条 ack payload，也无法在 `Unload(0x02)` 后输出具体 ack 明细。

本方案在不修改 DLL wire protocol 的前提下，新增一个轻量 `drainAckQueue`。

## 2. 目标

1. 不修改 DLL wire protocol。
2. 不新增 `CONTROL_ACK`。
3. 不新增 `broadcastId`。
4. 只处理现有 event pipe 中的 `cat=drain-ack`。
5. `Unload(0x02)` 后可按 `reached` 数量等待 drain ack。
6. 支持输出已收到的 drain ack payload，便于排障。
7. drain ack 不进入 detection/status/dll diagnostic 队列，避免互相阻塞。

## 3. 非目标

本阶段不做：

1. 不做 reload/pause/resume 的完成 ACK。
2. 不做精确 broadcastId 关联。
3. 不做 DLL 实例在线表。
4. 不做磁盘可靠队列。
5. 不因为 drain ack 超时阻塞 UnInit 太久。

## 4. 数据结构

在 `AmsiIpcRuntime::Impl` 中新增：

```cpp
std::mutex drainAckMutex;
std::condition_variable drainAckCv;
std::deque<std::string> drainAckQueue;
size_t drainAckQueueCapacity = 256;
std::atomic<uint64_t> drainAckReceived{0};
std::atomic<uint64_t> drainAckDropped{0};
```

`AmsiIpcRuntimeStats` 增加：

```cpp
uint64_t drainAckDropped = 0;
size_t drainAckQueueSize = 0;
```

## 5. DrainAck 入队逻辑

在 `SubmitEventPayload()` 中：

```cpp
if (kind == AmsiIpcPayloadKind::DrainAck) {
    drainAckReceived.fetch_add(1);

    {
        std::lock_guard<std::mutex> lock(drainAckMutex);
        if (drainAckQueue.size() >= drainAckQueueCapacity) {
            drainAckQueue.pop_front();
            drainAckDropped.fetch_add(1);
        }
        drainAckQueue.push_back(payload);
    }

    drainAckCv.notify_all();
    return;
}
```

策略：

- 队列满时丢弃最旧 ack，保留最新 ack。
- `drainAckReceived` 始终递增，表示总收到数量。
- `drainAckDropped` 表示由于队列容量限制丢掉的 ack 明细数量。

## 6. 等待接口

新增内部方法：

```cpp
bool WaitForDrainAck(uint32_t expectedCount,
                     uint32_t timeoutMs,
                     std::vector<std::string>& ackPayloads);
```

语义：

1. `expectedCount == 0` 直接返回 true。
2. 广播前记录 `drainAckReceived` 快照。
3. 等待本轮新增 ack 数量达到 `expectedCount`。
4. 收到 ack 时从 `drainAckQueue` 取出 payload 放入 `ackPayloads`。
5. 超时返回 false。
6. 即使返回 false，也保留已收到 payload，方便日志排查。

建议实现使用条件变量，而不是固定 `Sleep(100)` 轮询：

```cpp
bool WaitForDrainAck(uint32_t expectedCount,
                     uint32_t timeoutMs,
                     std::vector<std::string>& ackPayloads)
{
    if (expectedCount == 0) {
        return true;
    }

    const uint64_t start = drainAckReceived.load();
    const auto deadline = std::chrono::steady_clock::now()
        + std::chrono::milliseconds(timeoutMs);

    std::unique_lock<std::mutex> lock(drainAckMutex);

    while (drainAckReceived.load() - start < expectedCount) {
        while (!drainAckQueue.empty() && ackPayloads.size() < expectedCount) {
            ackPayloads.push_back(drainAckQueue.front());
            drainAckQueue.pop_front();
        }

        if (drainAckReceived.load() - start >= expectedCount) {
            break;
        }

        if (drainAckCv.wait_until(lock, deadline) == std::cv_status::timeout) {
            break;
        }
    }

    while (!drainAckQueue.empty() && ackPayloads.size() < expectedCount) {
        ackPayloads.push_back(drainAckQueue.front());
        drainAckQueue.pop_front();
    }

    return drainAckReceived.load() - start >= expectedCount;
}
```

## 7. Unload 流程

`AmsiIpcRuntime::Unload()` 调整为：

```cpp
result = Broadcast(0x02);
StoreBroadcastSummary("unload", timeoutMs, result);

std::vector<std::string> acks;
bool drained = WaitForDrainAck(result.reached, timeoutMs, acks);

InfoLogf3(..., "Unload broadcast reached=%lu drainAck=%lu lastError=%lu",
          result.reached,
          static_cast<unsigned long>(acks.size()),
          result.lastError);

for (const auto& ack : acks) {
    InfoLogf1(..., "Unload drain ack: %s", ack);
}
```

返回值建议：

- 广播失败：`Unload()` 返回 false。
- drain ack 超时：只打 warning，不让 `Unload()` 返回 false。

原因：DLL 可能已经退出、目标进程可能被杀、ack 可能丢失；不应让 `UnInit()` 长时间卡住或失败。

## 8. Stop 行为

`Stop()` 或 runtime 清理时需要唤醒等待方：

```cpp
{
    std::lock_guard<std::mutex> lock(drainAckMutex);
    drainAckQueue.clear();
}
drainAckCv.notify_all();
```

避免未来 `WaitForDrainAck()` 等待期间 runtime 停止导致等待线程无法醒来。

## 9. 统计导出

`GetStats()` 增加：

```cpp
stats.drainAckDropped = drainAckDropped.load();
{
    std::lock_guard<std::mutex> lock(drainAckMutex);
    stats.drainAckQueueSize = drainAckQueue.size();
}
```

## 10. 已知限制

1. 没有 `broadcastId`，无法严格证明某条 drain ack 属于哪一次 unload。
2. 通过“广播前计数快照 + 等待新增数量”降低误判。
3. 如果同时执行多次 unload，ack 归属可能不精确。
4. 本阶段只建议由单控制线程串行调用 unload。
5. reload/pause/resume 不使用该队列。

## 11. 建议落地顺序

1. `AmsiIpcRuntimeQueue.h` 增加 stats 字段。
2. `AmsiIpcRuntime.cpp::Impl` 增加 `drainAckQueue / mutex / cv / dropped`。
3. `SubmitEventPayload()` 中 `DrainAck` 分支改为入队并通知。
4. 增加 `WaitForDrainAck()` 内部方法。
5. `Unload()` 广播后调用 `WaitForDrainAck(reached, timeoutMs)`。
6. `GetStats()` 导出队列大小和 dropped。
7. `Stop()` 清理队列并通知等待者。

## 12. 当前阶段状态（2026-05-28 修订）

本方案当前仅作为 `Unload(0x02)` / drain-ack 后续增强预留，不进入当前业务阶段实现。

当前 `AmsiDetectTask::UnInit()` 只要求执行：

```text
PauseDetection(0x03)
StopAmsiIpcIfStarted()
```

暂不要求：

- 调用 `Unload(0x02)`。
- 等待 `drain-ack`。
- 因 drain ack 缺失阻塞 `UnInit()`。

后续如果重新启用 unload/drain-ack，应按本文第 7 节流程单独实现，并重新评审正常退出、异常退出和 DLL event pipe 关闭顺序。
