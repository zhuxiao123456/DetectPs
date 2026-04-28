# Phase 2 Batch 4: 事件与日志异步队列设计方案

## 1. 结论

接受架构审视意见，Phase 2 第四批进入设计固化阶段。

本批目标不是增强检测能力，而是继续做宿主稳定性治理：将 detection event 和关键 telemetry 从 `Scan()` 热路径中解耦，避免 PowerShell/AMSI 宿主被 pipe 写入、sentry 断连、日志洪泛、队列等待或 worker 退避拖慢。

第一版优先异步化：

- DetectionEvent
- timeout / reload / shutdown / faulted 等关键 telemetry

第一版暂不把所有 debug log 都接入队列。普通 debug log 保持 `OutputDebugStringA` 或采样丢弃，避免低价值日志洪泛挤压 detection 事件。

## 2. 开发边界

允许做：

- `AsyncEvent`
- `AsyncEventQueue`
- `AsyncEventSink`
- 非阻塞或近似非阻塞 `TryEnqueue()`
- 队列容量上限
- 单事件大小上限
- 优先级 drop policy
- dropped_count / metrics
- 后台 worker
- sentry 断连退避
- shutdown flush timeout
- DetectionEvent / 关键 telemetry 异步提交
- `async_event_queue_tests`
- `test_phase2_batch4.ps1`

禁止做：

- 检测规则增强
- session cache
- 样本窗口扫描
- Lua / PCRE2 重构
- worker-thread scan timeout
- 复杂 telemetry 后端协议
- 无限队列
- Scan 中同步写 pipe
- Scan 中同步 ConnectSentry
- Scan 中等待 sentry reconnect
- Scan 中等待 condition_variable
- Scan 中等待队列空间
- Scan 中访问磁盘日志

## 3. 热路径强约束

`Scan()` 热路径必须零等待。

允许：

- 短暂 `try_lock`
- 原子计数
- 固定内存 copy
- 失败立即返回

禁止：

- 等待队列空间
- 等待 `condition_variable`
- 等待 worker
- 等待 pipe
- 等待 sentry reconnect
- 等待磁盘日志

如果队列锁竞争严重，`TryEnqueue()` 必须失败并计数，不允许让 `Scan()` 等待。

## 4. EnqueueResult

`TryEnqueue()` 不返回裸 `bool`，必须返回可诊断原因：

```cpp
enum class EnqueueResult {
    Enqueued,
    DroppedQueueFull,
    DroppedLockContention,
    DroppedStopping,
    DroppedTooLarge
};
```

用途：

- 单元测试可明确断言 drop 原因
- telemetry 可区分队列满、锁竞争、停止态、单事件过大
- 线上排障可判断是容量问题、生命周期问题还是事件体积问题

## 5. 事件对象必须自包含

Scan 中入队的事件不能保存以下裸引用或借用视图：

- `RaspLuaContext*`
- `RuleSnapshot*`
- `std::string_view` 指向 scan 栈内存
- `IAmsiStream*`
- `AmsiRuleEngine*`
- `lua_State*`
- `PCRE2 match data*`

事件对象必须在入队前完成必要字段拷贝。

建议结构：

```cpp
enum class EventPriority {
    Detection,
    Telemetry,
    DiagLog
};

enum class EventType {
    Detection,
    RuntimeTelemetry,
    Diagnostic
};

struct AsyncEvent {
    EventPriority priority;
    EventType type;
    uint64_t timestamp;
    DWORD pid;
    DWORD tid;
    std::string ruleId;
    std::string decision;
    std::string contentName;
    std::string appName;
    std::string sampleHash;
    uint64_t sampleLen = 0;
    std::string reason;
    std::string compactJson;
    bool eventTruncated = false;
};
```

worker 线程发送时不得访问 scan 上下文、规则快照、Lua 上下文或 AMSI stream。

## 6. 单事件大小上限

除了队列容量，还必须限制单事件大小：

```cpp
struct AsyncEventQueueOptions {
    size_t maxEvents = 4096;
    size_t maxEventBytes = 16 * 1024;
};
```

第一版建议：

- 单事件最大 16KB
- 如现有 JSON 字段较多，可调整为 32KB
- 超过上限时优先截断低价值字段，而不是携带完整 payload
- 截断后标记 `eventTruncated=true`
- 如果截断后仍超过上限，`TryEnqueue()` 返回 `DroppedTooLarge`

DetectionEvent 不应该携带完整 sample 或完整 payload，只保留：

- `rule_id`
- `decision`
- `sample_hash`
- `sample_len`
- 截断后的 `content_name`
- `app_name`
- `pid`
- `tid`
- `reason`

## 7. 组件边界

### 7.1 AsyncEventQueue

职责：

- 多生产者入队
- 单消费者出队
- 容量控制
- 单事件大小限制
- 优先级丢弃
- dropped_count 统计
- stop / drain

不负责：

- AMSI 逻辑
- Lua 执行
- PCRE2 细节
- RuleSnapshot 生命周期
- EngineRuntime 状态机
- sentry pipe 写入

### 7.2 AsyncEventSink

职责：

- 后台 worker
- 调用同步发送回调
- sentry 断连退避
- shutdown flush timeout
- 聚合 metrics

不允许：

- 修改 `EngineState`
- 阻塞 `ScanGuard`
- 阻塞 reload / shutdown
- 持有 runtime mutex
- 访问正在释放的 engine 资源

## 8. 队列结构与 Drop Policy

第一版采用三个有界队列：

```cpp
std::deque<AsyncEvent> high;   // Detection
std::deque<AsyncEvent> medium; // Telemetry
std::deque<AsyncEvent> low;    // DiagLog
```

入队策略：

- Detection：有空间则入队；无空间时先丢一个 DiagLog；仍无空间丢一个 Telemetry；仍无空间丢当前 Detection，并增加 `dropped_detection_count`
- Telemetry：有空间则入队；无空间时先丢一个 DiagLog；仍无空间丢当前 Telemetry
- DiagLog：有空间则入队；无空间直接丢弃

出队策略：

- 优先 Detection
- 其次 Telemetry
- 最后 DiagLog

第一版不做复杂公平调度。低优先级公平发送作为后续优化项：

- 每发送 N 条 Detection，允许发送 1 条 Telemetry
- 每发送 M 条 Telemetry，允许发送 1 条 DiagLog

## 9. Worker 发送失败策略

worker 发送失败后不能逐条无限重试，避免队头阻塞。

发送失败策略：

- 增加 `events_send_failed_total`
- 增加 `sentry_disconnected_count`
- 当前事件丢弃，或最多有限重试一次
- 进入 backoff
- 不无限阻塞队列头部

禁止：

- 对同一事件无限重试
- 失败事件长期占住队头
- worker 忙等
- Scan 中同步重连

## 10. sentry 断连退避

退避策略：

- 首次失败：100ms
- 连续失败：200ms -> 500ms -> 1000ms -> 2000ms
- 最大退避：5000ms
- sentry 恢复后重置退避

退避期间：

- Scan 继续 `TryEnqueue()`
- 队列满按 drop policy 处理
- worker 不忙等

禁止：

- `while(true)` 立刻重连
- Scan 中同步 `ConnectSentry()`
- 每条事件都阻塞式重连

## 11. SendDetectionEvent 改造

现有同步发送逻辑必须拆成两层：

```cpp
EnqueueResult TrySubmitDetectionEvent(const DetectionEvent& event);
bool SendDetectionEventSyncWorkerOnly(const DetectionEvent& event);
```

Scan / Evaluate 热路径只允许调用：

```cpp
TrySubmitDetectionEvent(event);
```

后台 worker 内部调用：

```cpp
SendDetectionEventSyncWorkerOnly(event);
```

同步函数必须使用明确的危险命名，并写明注释：

```cpp
// Worker-only. Must never be called from Scan hot path.
bool SendDetectionEventSyncWorkerOnly(const DetectionEvent& event);
```

验证脚本必须检查：

- `Scan()` / `Evaluate()` 热路径不得直接调用 `SendDetectionEventSyncWorkerOnly`
- `Scan()` / `Evaluate()` 热路径不得直接写 pipe
- `Scan()` / `Evaluate()` 热路径不得同步 `ConnectSentry`

## 12. Metrics

本批至少记录以下原子计数器：

- `events_enqueued_total`
- `events_sent_total`
- `events_send_failed_total`
- `events_dropped_total`
- `dropped_detection_count`
- `dropped_telemetry_count`
- `dropped_diag_count`
- `queue_current_size`
- `queue_high_watermark`
- `sentry_disconnected_count`
- `worker_backoff_count`
- `shutdown_flush_timeout_count`
- `events_truncated_total`
- `enqueue_lock_contention_count`
- `enqueue_stopping_drop_count`
- `enqueue_too_large_drop_count`

计数器使用 `std::atomic<uint64_t>`，不依赖 sentry 是否可用。

当 sentry 恢复后，可将聚合统计作为关键 telemetry 发送。第一版可先只保留本地计数和 `OutputDebugStringA`。

## 13. 生命周期

### 初始化

顺序：

1. Engine 初始化完成
2. `AsyncEventSink::Start()`
3. worker 启动

如果 worker 启动失败：

- 不影响 Scan
- 记录 `event_sink_start_failed`
- 后续 `TryEnqueue()` 直接失败并增加 dropped_count

### 正常运行

流程：

```text
Scan -> TrySubmitDetectionEvent -> TryEnqueue -> return
worker -> SendDetectionEventSyncWorkerOnly -> fail/backoff/drop-or-send
```

### Shutdown

普通 shutdown：

1. 标记 queue stopping
2. `TryEnqueue()` 开始拒绝新事件，返回 `DroppedStopping`
3. worker drain 已有事件
4. 等待 flush timeout，默认 1000ms
5. 停止 worker
6. 丢弃剩余事件并聚合 dropped_count

### Inert / Unload

unload / inert 路径：

- flush timeout 默认 100ms-200ms
- 不做长 flush
- 不等待 sentry
- 尽快 stop
- 超时后丢弃剩余事件并计数

## 14. 测试方案

### 14.1 单元测试

新增：

- `async_event_queue_tests.cpp`

必须覆盖：

- `TryEnqueue()` 成功返回 `Enqueued`
- queue full 返回 `DroppedQueueFull`
- stopping 返回 `DroppedStopping`
- lock contention 返回 `DroppedLockContention`
- oversized event 返回 `DroppedTooLarge`
- 单事件超过上限后字段截断并标记 `eventTruncated`
- 截断后仍过大则 drop
- Detection 优先保留，DiagLog 优先丢弃
- DiagLog flood 不挤掉所有 Detection
- 队列完全满时 Detection 可被丢弃并增加 `dropped_detection_count`
- 出队优先级为 Detection -> Telemetry -> DiagLog
- metrics 计数准确
- stop 后拒绝新事件

### 14.2 Worker / Sink 测试

必须覆盖：

- worker 发送成功增加 `events_sent_total`
- worker 发送失败增加 `events_send_failed_total`
- 发送失败后进入 backoff
- 发送失败不无限卡住队头
- backoff 不 busy loop
- sentry 恢复后可继续发送
- shutdown flush 超时后退出
- worker stop 后不访问释放资源

### 14.3 热路径测试

必须覆盖：

- sentry 断连时 `TrySubmitDetectionEvent()` 快速返回
- 队列满时 `TrySubmitDetectionEvent()` 快速返回
- 多线程高并发入队不崩
- active scan count 不受事件发送影响

建议压力测试：

- 10 万次 Detection 入队
- DiagLog flood 下 Detection 仍可保留
- sentry 一直断开时 Scan 延迟 p95 不明显上升
- shutdown 时队列中有大量事件，flush 不超过 timeout

### 14.4 回归测试

必须继续通过：

- `engine_runtime_tests`
- `scan_budget_tests`
- `async_event_queue_tests`
- `rasp_mod_amsi.dll` Release 构建

## 15. 验收标准

### 构建验收

- `rasp_mod_amsi.dll` 构建通过
- `engine_runtime_tests` 通过
- `scan_budget_tests` 通过
- `async_event_queue_tests` 通过

### 热路径验收

- Scan 热路径只调用 `TrySubmitDetectionEvent()` / `TryEnqueue()`
- Scan 不直接写 pipe
- Scan 不同步 `ConnectSentry()`
- Scan 不等待 worker
- Scan 不等待 `condition_variable`
- Scan 不等待队列空间
- Scan 不访问磁盘日志
- Scan 不调用 `SendDetectionEventSyncWorkerOnly()`

### 队列验收

- 队列容量有上限
- 单事件大小有上限
- 队列满有 drop policy
- `TryEnqueue()` 返回可诊断原因
- Detection 优先级高于 Telemetry / DiagLog
- DiagLog flood 不挤掉所有 Detection
- Detection 被丢弃时 `dropped_detection_count` 增加
- oversized event 截断或按 `DroppedTooLarge` 丢弃

### 生命周期验收

- shutdown flush 有 timeout
- unload / inert 路径短 flush
- worker stop 后不访问释放资源
- stopping 后 `TryEnqueue()` 拒绝新事件
- 队列剩余事件被安全丢弃并聚合计数

### 断连验收

- sentry 断连不拖慢 Scan
- worker 进入 backoff
- worker 不 busy loop
- sentry 恢复后可以继续发送
- 发送失败不无限阻塞队头事件

### 边界验收

- 不做规则增强
- 不做 session cache
- 不做样本窗口扫描
- 不做 Lua / PCRE2 重构
- 不做复杂 telemetry 后端协议

## 16. 实施顺序

建议按以下顺序开发：

1. 写入本设计文档
2. 先写 `async_event_queue_tests.cpp`，定义 RED case
3. 新增 `async_event_queue.h/.cpp` 空骨架
4. 实现 `AsyncEvent` 自包含结构
5. 实现 `EnqueueResult`
6. 实现有界队列和 `TryEnqueue()`
7. 实现单事件大小限制和字段截断
8. 实现优先级 drop policy
9. 实现 metrics 计数器
10. 实现 `AsyncEventSink` worker 和发送回调模型
11. 实现 sentry 断连退避
12. 实现 shutdown flush timeout
13. 拆分 `TrySubmitDetectionEvent()` / `SendDetectionEventSyncWorkerOnly()`
14. 将 AMSI `Evaluate()` 命中事件改为 `TrySubmitDetectionEvent()`
15. 增加 `scripts/test_phase2_batch4.ps1`
16. 构建、单测、断连测试、压力测试
17. 独立 commit / push

## 17. 保留技术债

第一版不解决以下问题，但必须记录：

- 低优先级事件公平调度
- 所有 debug log 异步化
- 完整 telemetry 后端协议
- 事件批量压缩发送
- 更细粒度内存占用估算
- AppVerifier / PageHeap / TSAN 等强化验证自动化
