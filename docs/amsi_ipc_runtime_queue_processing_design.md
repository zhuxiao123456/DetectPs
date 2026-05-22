# AmsiIpcRuntime 队列化处理优化方案

## 1. 背景

当前 `module_amsi_detect` 的 `AmsiIpcRuntime.cpp` 在接收到 event/status payload 后，第一版只做业务日志记录：

```text
pipe worker -> 收到 payload -> 直接写业务日志
```

该实现适合 P1 真实 IPC 联调，但不适合生产化迁移。日志 IO、复杂 JSON 解析或后续 EDR 转换一旦变慢，会反向阻塞 pipe worker，影响 DLL 与 HostGuard/module 的通信热路径。

本方案只优化 `AmsiIpcRuntime` 内部处理模型，不改变 DLL wire protocol。

## 2. 优化目标

1. pipe worker 只负责读取 payload、基础校验、轻量分类和入队。
2. detection event、DLL diagnostic log、status 分离到独立队列。
3. 每类队列由独立 worker thread 消费，避免队头阻塞。
4. 保留当前日志行为，但日志写入不再发生在 pipe worker 中。
5. 为后续 EDR event 转换、DLL 实例状态表、broadcast ack 关联预留入口。

本阶段不改变：

- DLL wire protocol。
- rule pipe 行为。
- event/status payload 格式。
- AMSI provider 注册/反注册。
- GET_POLICY。
- EDR event 转换。
- 服务端上报。
- 磁盘可靠队列。

## 3. 当前问题

### 3.1 pipe worker 被日志 IO 阻塞

当前 event/status 到达后直接写业务日志。日志系统如果发生锁竞争、磁盘慢写或同步刷新，会拖慢 pipe worker。

### 3.2 event/status/diag 未分流

当前所有 payload 都走同一类日志路径，无法区分：

- detection event
- DLL diagnostic log
- drain ack
- unknown event
- DLL_LOADED
- RULE_LOAD_RESULT
- control status

### 3.3 缺少背压策略

event 风暴或 DLL diagnostic log 风暴时，当前没有明确的队列容量、字节预算和丢弃计数。

### 3.4 缺少生产状态观测

当前无法稳定输出：

- 各队列积压数量。
- 各队列当前字节数。
- dropped event/log/status 计数。
- 最近一次 worker 错误。
- 是否处于 degraded 状态。

## 4. 传输边界

当前 `AmsiEventChannel` / `AmsiControlStatusChannel` 使用固定缓冲区读取：

```cpp
char buffer[65536] = {};
ReadFile(pipe, buffer, sizeof(buffer) - 1, ...);
```

因此本阶段单条 event/status payload 最大按现有读取实现限制：

```cpp
size_t maxPayloadBytes = 64 * 1024 - 1;
```

本阶段明确选择方案 A：

- 维持现有约 64KB 单条 payload 限制。
- 不处理 `ERROR_MORE_DATA`。
- 不循环拼接大消息。
- 不扩展 wire protocol 或传输层语义。
- 超过 `maxPayloadBytes` 的 payload 拒绝并计数。

方案 B，即支持大于 64KB 的消息，需要改 channel 读取逻辑，处理 `ERROR_MORE_DATA`、循环读取、拼接 payload、超过 `maxPayloadBytes` 丢弃并计数。该方案属于传输层增强，不纳入本阶段。

## 5. 目标线程模型

```text
Named pipe worker threads
  -> 读取 raw payload
  -> 基础长度校验
  -> 轻量分类
  -> 入队或轻量计数
  -> 立即返回

DetectionEventWorker
  -> 消费 DetectionEventQueue
  -> 第一版写业务日志
  -> 后续接 EDR event 转换

DllDiagnosticLogWorker
  -> 消费 DllDiagnosticLogQueue
  -> 截断、限频、聚合后写业务日志

StatusWorker
  -> 消费 StatusQueue
  -> 第一版写业务日志
  -> 后续解析 DLL_LOADED / RULE_LOAD_RESULT / control ack

RuntimeDiag
  -> 记录 runtime 自身错误、队列丢弃、分类失败
```

## 6. 新增数据结构

### 6.1 AmsiIpcRuntimeQueueConfig

```cpp
struct AmsiIpcRuntimeQueueConfig {
    size_t maxPayloadBytes = 64 * 1024 - 1;

    size_t detectionQueueCapacity = 4096;
    size_t detectionQueueMaxBytes = 64 * 1024 * 1024;
    uint32_t detectionEnqueueTimeoutMs = 50;

    size_t dllDiagnosticLogQueueCapacity = 2048;
    size_t dllDiagnosticLogQueueMaxBytes = 16 * 1024 * 1024;
    size_t dllDiagnosticLogMaxLineBytes = 4 * 1024;
    uint32_t dllDiagnosticDuplicateWindowMs = 60 * 1000;

    size_t statusQueueCapacity = 1024;
    size_t statusQueueMaxBytes = 16 * 1024 * 1024;
    uint32_t statusEnqueueTimeoutMs = 50;
};
```

说明：

- `maxPayloadBytes` 与当前 64KB pipe 读取缓冲区对齐。
- 队列同时限制条数和总字节数。
- detection/status 使用有限等待，避免关键事件瞬时丢弃。
- diagnostic log 默认允许直接丢弃，避免诊断日志压垮检测链路。
- diagnostic log 写日志时默认最多输出 4KB，同时记录原始 `rawLen`。

### 6.2 AmsiIpcRuntimeStats

```cpp
struct AmsiIpcRuntimeStats {
    bool initialized = false;
    bool running = false;
    bool stopping = false;
    bool workersStarted = false;
    bool pipeStarted = false;

    uint64_t detectionReceived = 0;
    uint64_t detectionDropped = 0;
    uint64_t dllDiagReceived = 0;
    uint64_t dllDiagDropped = 0;
    uint64_t statusReceived = 0;
    uint64_t statusDropped = 0;
    uint64_t drainAckReceived = 0;
    uint64_t unknownEventReceived = 0;
    uint64_t oversizedPayloadDropped = 0;

    size_t detectionQueueSize = 0;
    size_t detectionQueueBytes = 0;
    size_t dllDiagQueueSize = 0;
    size_t dllDiagQueueBytes = 0;
    size_t statusQueueSize = 0;
    size_t statusQueueBytes = 0;

    std::string lastError;
    bool degraded = false;
};
```

并发访问要求：

- 计数器内部使用 `std::atomic<uint64_t>` 存储。
- `initialized/running/stopping/workersStarted/pipeStarted/degraded` 使用 atomic 或 runtime mutex 保护。
- `lastError` 使用 `statsMutex` 或 runtime mutex 保护。
- 队列 size/bytes 从队列内部加锁读取。
- `GetStats()` 返回快照，不暴露内部引用。
- `Start()` / `Stop()` 重置或更新状态时必须与 worker 并发更新兼容。

### 6.3 RuntimePayloadEnvelope

```cpp
enum class RuntimePayloadKind {
    Detection,
    DllDiagnosticLog,
    DrainAck,
    UnknownEvent,
    Status
};

struct RuntimePayloadEnvelope {
    RuntimePayloadKind kind;
    std::string rawJson;
    uint64_t receivedTimeMs = 0;
};
```

### 6.4 BoundedPayloadQueue

队列要求：

- 支持条数限制。
- 支持字节预算。
- 支持 stop 唤醒。
- 出队时必须正确扣减字节。
- clear/Stop 时必须清空并归零字节计数。

建议接口：

```cpp
class BoundedPayloadQueue {
public:
    bool Push(RuntimePayloadEnvelope item,
              uint32_t timeoutMs,
              bool waitWhenFull);

    bool TryPush(RuntimePayloadEnvelope item);
    bool Pop(RuntimePayloadEnvelope& out);
    void Stop();
    void StopAndDrop();
    void Clear();

    size_t Size() const;
    size_t Bytes() const;
};
```

`Pop(out)` 语义：

- 队列有数据：返回 true。
- 队列 empty 且未 stopped：阻塞等待。
- 队列 empty 且 stopped：返回 false。
- 队列 stopped 但仍有数据：继续返回 true，直到 drain 完。

如果需要立即丢弃剩余数据，调用 `StopAndDrop()`，不要复用 `Stop()` 表达两种语义。

## 7. Event 分类规则

event pipe payload 分类优先级：

```text
1. cat == "Detection"
      -> Detection

2. cat == "drain-ack"
      -> DrainAck

3. cat == "diag"
      -> DllDiagnosticLog

4. cat 为空或未知，且 sensor == "RaspLog"
      -> DllDiagnosticLog

5. otherwise
      -> UnknownEvent
```

要求：

- `cat` 优先于 `sensor`。
- `cat == "Detection"` 且 `sensor == "RaspLog"` 时必须归类为 `Detection`。
- `cat == "drain-ack"` 且 `sensor == "RaspLog"` 时必须归类为 `DrainAck`。
- JSON 解析失败归为 `UnknownEvent`，记录 runtime diag。
- 分类必须在 `maxPayloadBytes` 检查之后执行。
- 第一版可使用现有 JsonUtils 做 top-level parse；后续优化为 bounded top-level field extractor，只扫描 `cat/sensor/pattern/msgType`，避免完整 DOM parse 大 JSON。

## 8. DrainAck 处理

`DrainAck` 不进入 `DetectionEventQueue`，也不进入 `DllDiagnosticLogQueue`。

本阶段不做精确 `broadcastId` 关联，因为 wire protocol 仍是旧协议。

处理策略：

- pipe worker 中完成轻量计数 `drainAckReceived++`。
- 如果需要保留 raw payload，可进入 `StatusQueue` 或 RuntimeDiag。
- 迟到 ack、无 broadcastId ack 当前只记录，不计入同步 broadcast result。

后续如要做精确关联，应新增 `BroadcastAckTracker`，不要复用 detection/log 队列。

## 9. 入队策略

### 9.1 DetectionEventQueue

- 优先保留。
- 队列满时最多等待 `detectionEnqueueTimeoutMs`。
- 超时仍满则丢弃并增加 `detectionDropped`。
- 不允许无限阻塞 pipe worker。

### 9.2 DllDiagnosticLogQueue

- 队列满时直接丢弃。
- 增加 `dllDiagDropped`。
- dropped 汇总每 60 秒最多输出一次。
- 写日志时 rawJson 默认最多输出 4KB，并记录 `rawLen`。
- 对重复日志按 `desc` 或 `pattern + desc` 聚合。
- `ConfigPipeThread: CreateNamedPipeW failed GLE=5 - retrying in 1s` 这类高频重复日志必须聚合，避免每秒刷屏。
- Debug 级诊断日志应可配置关闭。

### 9.3 StatusQueue

- 队列满时最多等待 `statusEnqueueTimeoutMs`。
- 超时仍满则进入 degraded。
- 第一版可丢弃并增加 `statusDropped`。
- 后续对 `DLL_LOADED`、`RULE_LOAD_RESULT` 做覆盖式保留。

后续 coalescing key：

```text
key = dllInstanceId + pid + msgType
```

如果没有 `dllInstanceId`：

```text
key = pid + processStartTime + msgType
```

## 10. Worker 行为

### 10.1 DetectionEventWorker

第一版：

- 写业务日志。
- 更新处理计数。

后续：

- 转换为 EDR event。
- 投递业务事件总线。

禁止：

- 同步调用 `Stop`。
- 同步调用 `Reload`。
- 同步调用 `PauseDetection` / `ResumeDetection`。
- 发送网络请求。
- 长时间持有 `AmsiDetectTask` 业务锁。

### 10.2 DllDiagnosticLogWorker

第一版必须实现：

- 4KB 截断输出。
- 记录原始 `rawLen`。
- 重复日志聚合。
- dropped 汇总限频。

### 10.3 StatusWorker

第一版：

- 写业务日志。
- 更新处理计数。

后续：

- 解析 `DLL_LOADED`。
- 解析 `RULE_LOAD_RESULT`。
- 解析 control ack。
- 更新 DLL 实例表。

## 11. 生命周期语义

### 11.1 Start

`AmsiIpcRuntime::Start()` 顺序：

1. 校验规则快照已准备完成。
2. 初始化队列。
3. 启动 detection/status/diag worker。
4. 启动 rule/event/status pipe server。
5. 全部成功后再设置 `running=true`。

如果中途失败：

1. 停止已启动 pipe server。
2. Stop 队列。
3. join 已启动 worker。
4. Clear 队列。
5. `running=false`。
6. 返回 false，并填充 error。

### 11.2 Stop

`AmsiIpcRuntime::Stop(uint32_t timeoutMs)` 必须幂等，且 `timeoutMs` 必须用于 worker drain/join。

推荐语义：

1. 停止 pipe server，阻止新 payload。
2. 设置 `stopping=true`。
3. 队列 `Stop()`，唤醒 worker。
4. worker 不再等待新数据。
5. 在 `timeoutMs` 内尽量 drain 已有队列。
6. 超时后丢弃剩余队列，更新 dropped / lastError / degraded。
7. join worker。
8. Clear 队列。
9. `running=false`。
10. Stop 返回后不再写业务回调或业务日志。

### 11.3 UnInit

`AmsiDetectTask::UnInit()` 继续调用：

```cpp
m_amsiIpcRuntime.PauseDetection(1000, error);
m_amsiIpcRuntime.Stop(3000, error);
```

Runtime 内部负责停止 pipe、队列和 worker。

## 12. AmsiIpcRuntime 接口调整

建议在 `AmsiIpcRuntimeConfig` 中增加：

```cpp
AmsiIpcRuntimeQueueConfig queueConfig;
```

新增状态查询接口：

```cpp
AmsiIpcRuntimeStats GetStats() const;
```

保留现有接口：

```cpp
bool Init(const AmsiIpcRuntimeConfig& config, std::string& error);
bool Start(const AmsiRuleSnapshot& snapshot, std::string& error);
bool Stop(uint32_t timeoutMs, std::string& error);
bool PauseDetection(uint32_t timeoutMs, std::string& error);
bool UpdateRules(const AmsiRuleSnapshot& snapshot, std::string& error);
bool Reload(uint32_t timeoutMs, std::string& error);
bool IsRunning() const;
```

## 13. 建议新增文件

```text
src/module_amsi_detect/include/AmsiIpcRuntimeQueue.h
src/module_amsi_detect/src/AmsiIpcRuntimeQueue.cpp
src/module_amsi_detect/include/AmsiIpcPayloadClassifier.h
src/module_amsi_detect/src/AmsiIpcPayloadClassifier.cpp
```

为了降低业务工程接入风险，推荐新增独立文件，不继续扩大 `AmsiIpcRuntime.cpp`。

## 14. CMake 改动

在 `src/module_amsi_detect/CMakeLists.txt` 增加：

```cmake
src/AmsiIpcRuntimeQueue.cpp
src/AmsiIpcPayloadClassifier.cpp
```

不需要新增外部 link library。

## 15. 测试方案

### 15.1 单元级测试

如果业务工程暂不方便加测试目标，至少在本仓库增加独立测试或手工 harness 覆盖：

1. Detection event 分类。
2. `cat == "drain-ack"` 且 `sensor == "RaspLog"` 必须归类为 `DrainAck`。
3. `cat == "Detection"` 且 `sensor == "RaspLog"` 必须归类为 `Detection`。
4. `cat == "diag"` 归类为 `DllDiagnosticLog`。
5. `sensor == "RaspLog"` 兜底归类为 `DllDiagnosticLog`。
6. 非法 JSON 归类为 `UnknownEvent`，不进入 detection queue。
7. 队列条数满时丢弃。
8. 队列字节预算满时丢弃。
9. 超过 `maxPayloadBytes` 的 payload 被拒绝并计数。
10. Stop 时队列非空，worker 能退出。
11. Stop 时 worker 正在写日志，Stop 等待或超时行为符合预期。
12. Start 中途 pipe server 启动失败，已启动 worker 被回滚。
13. status queue 满时 `degraded=true`。
14. dll diag 风暴不会影响 detection 入队。
15. GetStats() 并发调用无数据竞争。

### 15.2 联调测试

1. 启动 HostGuard/module。
2. 确认 pipe 创建成功：

```powershell
[System.IO.Directory]::GetFiles("\\.\pipe\") | Where-Object { $_ -match "amsi_detect" }
```

3. 启动 PowerShell 触发检测。
4. 确认 detection event 进入 DetectionEventWorker。
5. 确认 DLL diagnostic log 进入 DllDiagnosticLogWorker。
6. 确认 `RULE_LOAD_RESULT` 进入 StatusWorker。
7. 压测大量 diag log，确认 rule/status pipe 不被日志写入阻塞。
8. Stop/UnInit 后确认 worker 退出，不再持续写日志。

## 16. 实施顺序

1. 新增 payload classifier。
2. 新增 bounded queue。
3. 在 `AmsiIpcRuntime` 增加 queue config 和 stats。
4. 增加 detection/status/diag worker。
5. 修改 event pipe callback：分类后入队或计数。
6. 修改 status pipe callback：入 status queue。
7. 将原直接写日志逻辑移动到 worker。
8. 增加 Stop 队列唤醒、drain、worker join。
9. 增加 stats 日志或状态导出。
10. 进行真实 PowerShell + DLL 联调。

## 17. 验收标准

满足以下条件即可认为本阶段完成：

- pipe worker 不直接执行日志 IO。
- detection、status、DLL diagnostic log 三类处理线程分离。
- 队列同时限制条数和字节数。
- queue full 有明确丢弃/等待策略和计数。
- `maxPayloadBytes` 与当前 64KB 读取限制一致。
- Stop 能按 `timeoutMs` drain/join worker。
- Stop 后 worker 全部退出。
- GetStats() 并发读取无数据竞争。
- DLL diag 高频重复日志有截断和限频。
- PowerShell 仍可检出。
- `RULE_LOAD_RESULT` 仍可接收。
- DLL diagnostic log 仍可写业务日志。
- 不改变 DLL wire protocol。
