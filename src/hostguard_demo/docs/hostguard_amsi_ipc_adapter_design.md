# HostGuard AMSI IPC Adapter 接口设计方案

## 1. 背景

当前需要把 demo/rasp_sentry 侧的 AMSI 通信能力迁移到 HostGuard 程序中。

前提假设：

- 规则由 HostGuard 读取、组装和校验完成。
- 策略状态由 HostGuard 决定和维护。
- HostGuard 启动时有 init 流程，退出时有 uninit 流程。
- 通信模块负责创建 rules/event/status/control 等 IPC 通道。
- 通信模块只负责 IPC 生命周期、规则响应、事件接收、状态接收、控制广播，不负责业务决策。

目标：提供一组 HostGuard 可调用的稳定接口，避免 HostGuard 直接依赖 `RuleServer`、`NamedPipeServerPool`、`AmsiRuleChannel` 等底层对象。

## 2. 设计边界

通信模块负责：

- 初始化和关闭 AMSI IPC 通道。
- 响应 DLL 的 `GET_RULES` / `GET_ALL_RULES`。
- 接收 DLL 上报的 event。
- 接收 DLL 上报的 control status。
- 向已加载 DLL 广播 reload / unload / pause / resume。
- 保存当前策略状态，供广播审计、状态对齐和后续扩展使用。
- 提供通信模块自身状态和计数。

通信模块不负责：

- 不读取规则文件。
- 不决定策略是否开启。
- 不做 EDR event 转换。
- 不修改 DLL 上报的 event/status 原文。
- 不做日志落盘策略。
- 不做服务端上报。

HostGuard 是业务真相源：

- 规则来源。
- 策略开关。
- 日志落盘。
- EDR event 转换。
- 审计。
- 服务端上报。

## 3. 模块结构

建议新增 facade：

```text
hostguard_amsi_ipc_adapter.h
hostguard_amsi_ipc_adapter.cpp
```

内部组合：

```text
HostGuardAmsiIpcAdapter
  - AmsiIpcHost
  - HostGuardRuleProvider
  - HostGuardEventSink
  - HostGuardControlStatusSink
  - EventClassifier
  - DetectionEventQueue
  - DllDiagnosticLogQueue
  - StatusQueue
  - AdapterDiagRingBuffer
  - DetectionForwarderThread
  - StatusForwarderThread
  - DllDiagnosticLogForwarderThread
```

其中：

- `HostGuardRuleProvider` 实现 `amsi_ipc::IAmsiRuleProvider`。
- `HostGuardEventSink` 在 pipe worker 线程中读取 event pipe raw payload，先做最小分类，再投递到 adapter 内部队列。
- `HostGuardControlStatusSink` 在 pipe worker 线程中读取 raw status，并投递到 adapter 队列。
- `DllDiagnosticLogQueue` 只承载 DLL 通过 event pipe 上报的诊断日志，不承载 adapter 自身日志。
- `AdapterDiagRingBuffer` 承载 adapter 自身诊断、错误和慢 callback 记录，用于 `GetStatus()` 或可选诊断 callback。
- `HostGuardAmsiIpcAdapter` 是 HostGuard 主程序调用的统一入口。
- callback 不在 pipe worker 线程中直接执行。

## 4. 生命周期状态机

状态机：

```text
New
  -> Init()
Initialized
  -> Start()
Running
  -> Stop()
Stopped
  -> Start() / Destroy

Faulted
  -> Stop()
```

语义：

- `Init()` 只初始化内存对象、provider、sink、队列、配置；不创建 pipe 监听线程。
- `Init()` 只允许成功调用一次；重复调用返回 `false`，`error` 写明当前状态。
- `UpdateRules()` 允许在 `Start()` 前调用，推荐在 `Start()` 前完成。
- `SetDetectionEnabled()` 允许在 `Start()` 前调用，推荐在 `Start()` 前完成。
- `Start()` 创建 rule/event/status/control pipe 线程和 forwarder 线程。
- `Start()` 成功后进入 `Running`。
- `Start()` 失败必须回滚已创建资源，关闭已创建 pipe/thread，并进入 `Faulted` 或回到 `Initialized`，实现时需二选一并保持一致；建议进入 `Faulted`。
- `Stop()` 幂等。
- `Stop()` 停止接收新连接，唤醒阻塞 pipe，等待工作线程退出，等待 forwarder 线程退出。
- `Stop()` 受 `stopTimeoutMs` 限制。
- `Stop()` 后不再触发 HostGuard callback。
- `Stop()` 承担 HostGuard uninit 语义，不额外暴露 `Uninit()`。
- adapter 析构时应自动调用 `Stop()`，作为兜底清理；HostGuard 正常流程仍必须显式调用 `Stop()`。
- `PauseDetection()` / `ResumeDetection()` / `Reload()` / `Unload()` 仅在 `Running` 状态允许调用；未 `Start()` 时返回失败结果。
- HostGuard 重启 IPC 时必须先 `Stop()`，再 `Start()`；旧线程和旧 pipe handle 必须在 `Stop()` 内关闭。

HostGuard 对应关系：

```text
HostGuard init
  -> adapter.Init()
  -> adapter.SetDetectionEventCallback()
  -> adapter.SetDllDiagnosticLogCallback()
  -> adapter.SetStatusCallback()
  -> adapter.SetAdapterDiagCallback()    // optional
  -> adapter.UpdateRules()
  -> adapter.SetDetectionEnabled()
  -> adapter.Start()

HostGuard uninit
  -> adapter.Stop()
```

## 5. 主接口

```cpp
enum class DetectionQueueFullPolicy {
    DropImmediately,
    WaitThenDrop,
    BlockForever
};

enum class QueueFullPolicy {
    DropImmediately,
    WaitThenDrop,
    BlockForever
};

struct HostGuardAmsiIpcConfig {
    bool useProductionPipes = true;

    int rulePipeThreads = 8;
    int eventPipeThreads = 4;
    int statusPipeThreads = 4;

    size_t maxRuleResponseBytes = 4 * 1024 * 1024;
    size_t maxEventBytes = 1024 * 1024;
    size_t maxStatusBytes = 256 * 1024;

    size_t detectionEventQueueCapacity = 4096;
    size_t dllDiagnosticLogQueueCapacity = 8192;
    size_t statusQueueCapacity = 1024;
    size_t adapterDiagRingCapacity = 1024;

    size_t detectionEventQueueMaxBytes = 64 * 1024 * 1024;
    size_t dllDiagnosticLogQueueMaxBytes = 16 * 1024 * 1024;
    size_t statusQueueMaxBytes = 16 * 1024 * 1024;

    uint32_t stopTimeoutMs = 3000;
    uint32_t callbackTimeoutMs = 100;
    uint32_t detectionEnqueueTimeoutMs = 50;
    uint32_t statusEnqueueTimeoutMs = 50;

    DetectionQueueFullPolicy detectionQueueFullPolicy = DetectionQueueFullPolicy::WaitThenDrop;
    bool dropDllDiagnosticLogOnQueueFull = true;
    QueueFullPolicy statusQueueFullPolicy = QueueFullPolicy::WaitThenDrop;
    bool failStartIfPipeSecurityInvalid = true;
};

enum class HostGuardAmsiMessageKind {
    Detection,
    DiagnosticLog,
    DrainAck,
    Unknown
};

struct HostGuardAmsiEventEnvelope {
    HostGuardAmsiMessageKind kind = HostGuardAmsiMessageKind::Unknown;
    std::string rawJson;
    std::string cat;
    std::string sensor;
    std::string pattern;
    std::string broadcastId;
};

struct HostGuardAmsiAdapterDiag {
    std::string timestamp;
    std::string level;
    std::string component;
    std::string message;
};

struct HostGuardAmsiBroadcastResult {
    uint32_t attempted = 0;
    uint32_t delivered = 0;
    uint32_t failed = 0;
    uint32_t timeout = 0;
    uint32_t acked = 0;
    uint32_t elapsedMs = 0;

    std::string broadcastId;
    std::string command;
    std::string policyVersion;
    std::string ruleVersion;
    std::string error;
};

struct HostGuardAmsiAckInfo {
    std::string broadcastId;
    std::string instanceId;
    std::string command;
    std::string rawJson;
};

class BroadcastTracker {
public:
    bool BeginBroadcast(const std::string& broadcastId,
                        const std::string& command,
                        uint32_t attempted,
                        std::string& error);

    void OnAck(const std::string& broadcastId, const HostGuardAmsiAckInfo& ack);

    HostGuardAmsiBroadcastResult WaitResult(const std::string& broadcastId,
                                            uint32_t timeoutMs);

    void ExpireOldBroadcasts();
};

struct HostGuardAmsiIpcStatus {
    bool initialized = false;
    bool started = false;
    bool stopping = false;
    bool productionPipes = false;

    uint64_t ruleRequests = 0;
    uint64_t ruleRequestUnsupported = 0;
    uint64_t eventReceived = 0;
    uint64_t detectionEventReceived = 0;
    uint64_t dllDiagnosticLogReceived = 0;
    uint64_t drainAckReceived = 0;
    uint64_t drainAckCorrelated = 0;
    uint64_t drainAckUncorrelated = 0;
    uint64_t unknownEventReceived = 0;
    uint64_t statusReceived = 0;
    uint64_t detectionEventDropped = 0;
    uint64_t dllDiagnosticLogDropped = 0;
    uint64_t unknownEventDropped = 0;
    uint64_t statusDropped = 0;
    uint64_t adapterDiagDropped = 0;

    std::string lastError;
    std::string lastRuleVersion;
    std::string lastRuleHash;
    std::string lastPolicyVersion;
    std::string lifecycleState;
};

class HostGuardAmsiIpcAdapter {
public:
    bool Init(const HostGuardAmsiIpcConfig& config, std::string& error);
    bool Start(std::string& error);
    void Stop();

    bool UpdateRules(std::string allRulesJson,
                     std::string amsiRulesJson,
                     std::string version,
                     std::string hash,
                     std::string& error);

    bool SetDetectionEnabled(bool enabled,
                             std::string policyVersion,
                             std::string& error);

    bool Reload(uint32_t timeoutMs, HostGuardAmsiBroadcastResult& result);
    bool PauseDetection(uint32_t timeoutMs, HostGuardAmsiBroadcastResult& result);
    bool ResumeDetection(uint32_t timeoutMs, HostGuardAmsiBroadcastResult& result);
    bool Unload(uint32_t timeoutMs, HostGuardAmsiBroadcastResult& result);

    void SetDetectionEventCallback(std::function<void(const HostGuardAmsiEventEnvelope& event)> cb);
    void SetDllDiagnosticLogCallback(std::function<void(const HostGuardAmsiEventEnvelope& log)> cb);
    void SetStatusCallback(std::function<void(const std::string& rawJson)> cb);
    void SetAdapterDiagCallback(std::function<void(const HostGuardAmsiAdapterDiag& diag)> cb);

    std::vector<HostGuardAmsiAdapterDiag> GetRecentAdapterDiag() const;
    HostGuardAmsiIpcStatus GetStatus() const;
};
```

说明：

- 广播接口返回结构体，不返回字符串 summary。
- 字符串日志展示由 HostGuard 在上层转换。
- `SetDetectionEnabled()` 不等于把策略混进规则 JSON；本阶段只让 adapter 保存 HostGuard 当前策略状态，用于广播审计和状态对齐。新 DLL 查询策略属于方案 B，当前不实现。
- 当前 DLL 的检测事件、诊断日志和少量 ack 类 payload 复用同一个 event pipe；HostGuard 不应按 pipe 名直接判定业务类型，必须由 adapter 按 payload 字段分类后再回调。
- adapter 自身诊断不进入 `DllDiagnosticLogQueue`，避免和 DLL 上报日志混淆；adapter 自身诊断写入 `AdapterDiagRingBuffer`，必要时再通过 `SetAdapterDiagCallback()` 投递。

## 6. HostGuard 启动流程

推荐流程：

```cpp
HostGuardAmsiIpcConfig config;
config.useProductionPipes = true;

std::string error;

if (!adapter.Init(config, error)) {
    // HostGuard 记录 fatal / degraded
    return;
}

adapter.SetDetectionEventCallback([](const HostGuardAmsiEventEnvelope& event) {
    // 只投递到 HostGuard security event queue，不在这里落盘/入库/上报。
});

adapter.SetDllDiagnosticLogCallback([](const HostGuardAmsiEventEnvelope& log) {
    // 只投递到 HostGuard DLL diagnostic log queue，不在这里落盘/上报。
});

adapter.SetStatusCallback([](const std::string& rawJson) {
    // 只投递到 HostGuard status queue，不在这里做阻塞解析。
});

adapter.SetAdapterDiagCallback([](const HostGuardAmsiAdapterDiag& diag) {
    // 可选：只投递 adapter 自身诊断，不和 DLL 诊断日志混用。
});

if (!adapter.UpdateRules(allRulesJson, amsiRulesJson, version, hash, error)) {
    adapter.Stop();
    return;
}

if (!adapter.SetDetectionEnabled(policyEnabled, policyVersion, error)) {
    adapter.Stop();
    return;
}

if (!adapter.Start(error)) {
    adapter.Stop();
    return;
}
```

原则：

- callback 中不做重活。
- `UpdateRules()` 在 `Start()` 前完成。
- 策略状态在 `Start()` 前注入。
- `Start()` 失败必须 `Stop()` 回滚。
- HostGuard uninit 必须调用 `Stop()`。

## 7. 线程模型

```text
HostGuard main thread
  -> Init / Start / Stop / UpdateRules / Pause / Resume / Reload / Unload

Rule pipe worker threads
  -> 本阶段处理 GET_RULES / GET_ALL_RULES
  -> 只读规则快照；策略快照仅用于本阶段广播审计和状态对齐

Event pipe worker threads
  -> 读取 event pipe raw payload
  -> 做传输级限制
  -> 解析最小 JSON 字段 cat/sensor/pattern
  -> 分类为 Detection / DiagnosticLog / DrainAck / Unknown
  -> 投递 detection event queue / DLL diagnostic log queue / status ack handler
  -> 不调用 HostGuard callback

Status pipe worker threads
  -> 读取 raw status
  -> 做传输级限制
  -> 投递 status queue
  -> 不调用 HostGuard callback

Detection forwarder thread
  -> 从 detection event queue 取消息
  -> 调用 HostGuard detection callback

Status forwarder thread
  -> 从 status queue 和 ack handler 取消息
  -> 调用 HostGuard status callback

DLL diagnostic log forwarder thread
  -> 从 DLL diagnostic log queue 取消息
  -> 调用 HostGuard DLL diagnostic log callback

Adapter diag path
  -> adapter 自身诊断写入 AdapterDiagRingBuffer
  -> 可选触发 AdapterDiagCallback
```

callback 超时：

- `callbackTimeoutMs` 用于记录慢 callback。
- C++ 无法安全强杀 callback；实现上只记录耗时和慢调用计数。
- HostGuard callback 必须只做轻量投递。
- detection、status、DLL diagnostic log 使用独立 forwarder，任一类 callback 慢或阻塞时不能造成其他类别队头阻塞。
- adapter 自身诊断不依赖上述业务 forwarder，避免故障路径反向阻塞业务队列。
- HostGuard callback 内禁止同步反调 `adapter.Stop()` / `Start()` / `Reload()` / `Unload()` / `PauseDetection()` / `ResumeDetection()`。
- 如果 callback 需要触发控制动作，必须投递到 HostGuard 控制线程异步执行。

禁止同步反调的原因：

```text
StatusForwarderThread
  -> 调用 StatusCallback
      -> StatusCallback 同步调用 adapter.Stop()
          -> Stop 等待 StatusForwarderThread 退出
              => 自等待死锁
```

## 8. RuleProvider 快照语义

规则快照使用整体结构，不分散持有多段字符串：

```cpp
struct HostGuardRuleSnapshot {
    std::string allRulesJson;
    std::string amsiRulesJson;
    std::string version;
    std::string hash;
};

std::shared_ptr<const HostGuardRuleSnapshot> snapshot_;
mutable std::shared_mutex mutex_;
```

语义：

- `UpdateRules()` 构造完整新 snapshot。
- 校验 `allRulesJson` / `amsiRulesJson` / `version` / `hash` 是否满足 HostGuard 约束。
- 校验通过后一次性 swap。
- `BuildRulesResponse()` 与 `UpdateRules()` 并发时，要么返回旧完整快照，要么返回新完整快照，禁止返回半更新状态。
- `UpdateRules()` 失败不污染旧快照。
- `Reload()` 广播失败不回滚规则快照，由 HostGuard 决定是否重试广播。
- `hash` 由 HostGuard 生成，通信层不重新计算。
- DLL 上报的 version/hash 应可与 HostGuard 审计对齐。

命令语义：

- `GET_ALL_RULES` 返回 `allRulesJson`。
- `GET_RULES` 返回 `amsiRulesJson`。
- 后续如采用方案 B，可增加 `GET_POLICY`。
- 未知命令返回 `UNSUPPORTED_COMMAND`，并增加 `ruleRequestUnsupported` 计数。
- 没有规则快照时返回明确错误 `RULES_NOT_READY`，不返回空 JSON 伪装成功。
- 规则为空但合法时，返回 HostGuard 定义的合法空规则 envelope，并带 version/hash。

## 9. Event Pipe 复用与分类

当前 DLL 的 event pipe 不是纯检测事件通道。`amsi_detect_events` 里至少会出现以下 payload：

- 检测事件：`cat == "Detection"`。
- DLL 诊断日志：`cat == "diag"`，通常同时满足 `sensor == "RaspLog"`，AMSI 日志常见 `pattern == "amsi-log"`。
- unload / drain ack：例如 `cat == "drain-ack"`；新协议必须携带 `broadcastId`，旧协议没有 `broadcastId` 时只能记为 uncorrelated ack。
- 其他未知 payload：归类为 `Unknown`，记录计数，默认不进入安全事件队列。

分类规则：

```text
raw event pipe payload
  -> parse minimal JSON fields: cat / sensor / pattern
  -> cat == "Detection"
       => Detection
  -> cat == "drain-ack"
       => DrainAck
  -> cat == "diag"
       => DiagnosticLog
  -> cat is empty/unknown && sensor == "RaspLog"
       => DiagnosticLog
  -> otherwise
       => Unknown
```

约束：

- HostGuard 不应通过 pipe 名判断 payload 是检测事件还是日志。
- adapter 只读取分类所需的最小字段，不修改 `rawJson`。
- `cat` 优先级高于 `sensor`；`sensor == "RaspLog"` 只能作为兼容兜底，不能覆盖已知 `cat`。
- 分类失败或 JSON 非法时归类为 `Unknown`，按未知事件计数和限流策略处理。
- `Detection` 进入安全事件处理链路，用于 EDR event 转换、入库、上报。
- `DiagnosticLog` 进入 DLL 诊断日志链路，用于本地日志、排障和低优先级上报。
- `DrainAck` 不应作为安全事件入库，可路由到 status/ack 处理逻辑或单独计数。
- `DrainAck` 如果携带 `broadcastId`，必须与当前或历史 `HostGuardAmsiBroadcastResult.broadcastId` 关联；无法关联时增加 `drainAckUncorrelated`，不能计入精确 `acked`。

短期不新增 named pipe 日志通道，保持当前 DLL wire 兼容；但 adapter 内部必须拆分 detection/DLL log 队列，避免日志风暴挤占检测事件。

## 10. Event / Status 队列与背压

pipe worker 不直接执行 HostGuard callback。

处理流程：

```text
pipe worker
  -> read raw bytes
  -> size check / empty check
  -> classify event pipe payload when needed
  -> enqueue to typed queue

typed forwarder threads
  -> dequeue from detection/status/DLL log queues independently
  -> HostGuard callback
```

detection event 队列满：

- 不能同时承诺“永不丢弃”和“永不阻塞”；实现必须明确选择背压策略。
- 默认 `detectionQueueFullPolicy = DetectionQueueFullPolicy::WaitThenDrop`，pipe worker 最多等待 `detectionEnqueueTimeoutMs`。
- 等待后仍无空间时，丢弃当前 detection event，增加 `detectionEventDropped`，写入 `AdapterDiagRingBuffer`，并把状态标记为 degraded。
- 如果配置为 `DropImmediately`，队列满时立即丢弃、计数并写 adapter diag。
- 如果配置为 `BlockForever`，实现必须接受 event pipe worker 被反向阻塞；仅在 HostGuard 明确要求检测事件绝不丢弃时使用。
- 如果业务既要求检测事件绝不丢弃又不能阻塞 pipe worker，必须实现持久化溢出队列；当前阶段不默认提供。
- 不允许静默丢弃 detection event。

DLL diagnostic log 队列满：

- 默认 `dropDllDiagnosticLogOnQueueFull = true`。
- DLL debug/diagnostic log 可丢弃。
- 增加 `dllDiagnosticLogDropped` 计数。
- 不允许 DLL diagnostic log 反向阻塞 detection event 接收。

status 队列满：

- 默认 `statusQueueFullPolicy = QueueFullPolicy::WaitThenDrop`，最多等待 `statusEnqueueTimeoutMs`。
- `RULE_LOAD_RESULT`、`DLL_LOADED`、policy ack 不建议直接丢弃。
- 可采用同 instance 状态覆盖旧值。
- 或进入 degraded 状态并记录 `lastError`。
- 当前 Phase 1 skeleton 不使用无限阻塞作为默认行为，避免 mock 注入口或测试线程 hang。

队列容量限制：

- detection event、DLL diagnostic log、status 队列必须同时受条数和字节预算限制。
- 入队判断必须同时检查 queue count limit 和 queue bytes limit。
- `maxEventBytes` / `maxStatusBytes` 只限制单条消息大小，不能替代队列总字节预算。
- 默认字节预算：
  - `detectionEventQueueMaxBytes = 64 * 1024 * 1024`。
  - `dllDiagnosticLogQueueMaxBytes = 16 * 1024 * 1024`。
  - `statusQueueMaxBytes = 16 * 1024 * 1024`。
- 队列出队时必须扣减对应 payload 字节数，避免长期内存计数漂移。

`Stop()` 行为：

- 停止接收新消息。
- 设置 `stopping=true`，拒绝新的入队和新的控制广播。
- 停止 pipe worker，并唤醒阻塞 read / enqueue。
- 尝试 drain detection/DLL log/status 队列，受 `stopTimeoutMs` 限制。
- 通知 detection/status/DLL log forwarder 退出。
- forwarder 退出前必须等待当前 in-flight callback 返回。
- 超时后停止等待，剩余未处理消息计入 dropped 或 abandoned 计数；实现不能强杀正在执行的 callback，只能记录超时并进入 degraded。
- `Stop()` 返回后不再触发 callback。
- HostGuard 必须在 `adapter.Stop()` 返回后，才能销毁 callback 捕获的对象。

adapter 自身诊断：

- adapter 自身诊断写入 `AdapterDiagRingBuffer`。
- ring 满时覆盖最旧记录或增加 `adapterDiagDropped`，具体实现二选一并在状态中暴露。
- adapter 自身诊断不写入 `DllDiagnosticLogQueue`，也不走 DLL diagnostic log callback。

## 11. Event / Status 原样转发边界

“原样转发”指通信层不修改业务 JSON 内容。

通信层仍可做传输级防护：

- 最大消息长度限制。
- 空消息拒绝。
- UTF-8 / 字节合法性检查。
- 超大消息拒绝或截断，具体策略由配置决定。
- pipe read 超时。
- 基础计数和错误码记录。

通信层禁止：

- 修改 JSON 字段。
- escape/unescape。
- 注入 HostGuard 字段。
- 做 EDR event 转换。
- 做业务落盘。

## 12. Pipe Security 约束

`failStartIfPipeSecurityInvalid = true` 时，`Start()` 必须校验关键 pipe 的安全描述符。安全描述符创建失败或校验失败时，`Start()` 必须失败并回滚已创建资源。

control pipe 是最高风险通道，因为它可以触发 reload / unload / pause / resume。本阶段 control pipe 必须满足：

- 只允许 `SYSTEM`、`Administrators`、HostGuard 服务身份写入。
- 禁止 `Everyone` 写入。
- 禁止 `Authenticated Users` 写入。
- 禁止普通低权限用户写入。
- 安全描述符创建失败时，`Start()` 必须失败。
- 如果平台或部署模式无法表达 HostGuard 服务身份，必须至少限制为 `SYSTEM` 和 `Administrators`，并在 adapter diag 中记录降级原因。

rule/event/status pipe 权限需要结合 DLL 运行身份确定，但仍必须遵守：

- 不授予无关用户写 control 能力。
- event/status pipe 可允许 DLL 运行身份写入，但必须配合消息大小限制、队列预算和分类计数。
- rule pipe 可允许 DLL 运行身份读取规则，但不能允许未授权用户覆盖规则响应。

## 13. 策略关闭与新进程语义

本阶段固定实现方案 A 的最小子集：只通过 0x03 / 0x04 广播控制已经加载 DLL 的 pause/resume。当前暂不实现 HostGuard/EDR unregister/register AMSI provider，也暂不覆盖策略关闭后新启动 PowerShell 的加载行为。方案 B 只作为后续扩展记录，不进入本阶段接口承诺和测试用例。

必须区分两类进程：

- A：已经加载 DLL 的进程。
- B：策略关闭后新启动、后来才加载 DLL 的进程。

广播只覆盖 A，不覆盖 B。

### 完整方案 A：策略关闭时 unregister AMSI provider

完整方案 A 包含 register/unregister，但本阶段只实现其中的已加载 DLL 广播控制。本节描述完整目标和当前取舍。

策略关闭：

- HostGuard 保存 `policyEnabled=false`。
- HostGuard 广播 0x03 pause 给已加载 DLL。
- 完整方案 A 中 HostGuard 执行 unregister，避免新 PowerShell 加载 provider；本阶段暂不实现该步骤。
- 已加载实例进入 paused/inert。
- 本阶段不承诺新进程不加载 DLL。

策略开启：

- HostGuard 保存 `policyEnabled=true`。
- 完整方案 A 中 HostGuard 重新 register AMSI provider；本阶段暂不实现该步骤。
- HostGuard 广播 0x04 resume 给仍存活实例。
- 本阶段不处理新进程 provider 注册状态。

完整方案优点：语义干净。

完整方案代价：register/unregister 涉及系统状态、权限、失败恢复和审计。

### 方案 B：AMSI provider 始终注册，新 DLL 查询策略

本阶段不实现该方案。

策略关闭：

- HostGuard 保存 `policyEnabled=false`。
- HostGuard 广播 0x03 pause 给已加载 DLL。
- 新加载 DLL 第一次 `GET_POLICY` 时得到 disabled 状态。
- DLL 加载但不检测。

策略开启：

- HostGuard 保存 `policyEnabled=true`。
- HostGuard 广播 0x04 resume。
- 新加载 DLL `GET_POLICY` 后进入检测。

该方案需要新增独立策略命令：

```text
GET_POLICY
GET_RULES
GET_ALL_RULES
```

不推荐把策略塞进规则 JSON。

### 当前建议

当前阶段采用方案 A 的最小子集，测试用例只覆盖已加载 DLL 的 pause/resume 广播，不覆盖 unregister/register，也不覆盖策略关闭后新启动 PowerShell。

如果后续不希望频繁 register/unregister，再实现方案 B 的 `GET_POLICY`。无论未来选择哪种，策略状态的真相必须保存在 HostGuard/adapter 当前状态中，不能只依赖广播是否送达。

## 14. 策略广播接口

策略关闭/开启：

```cpp
bool PauseDetection(uint32_t timeoutMs, HostGuardAmsiBroadcastResult& result);
bool ResumeDetection(uint32_t timeoutMs, HostGuardAmsiBroadcastResult& result);
```

语义：

- `PauseDetection` 广播 0x03。
- `ResumeDetection` 广播 0x04。
- best effort。
- 不保证所有 DLL 一定收到。
- 结果写入结构体，供 HostGuard 审计、入库、上报。
- 每次广播必须生成唯一 `broadcastId`，写入 `HostGuardAmsiBroadcastResult.broadcastId`。
- 新协议下 DLL ack/status/drain-ack 应回带相同 `broadcastId`，adapter 只把可关联 ack 计入 `acked`。
- 旧协议 ack 如果没有 `broadcastId`，只能计入 `drainAckUncorrelated` 或兼容计数，不能用于精确证明本次广播送达。
- `broadcastId` 至少在 adapter 进程生命周期内唯一；建议格式为 `{utcTimestamp}-{monotonicCounter}-{random}`。
- adapter 内部必须使用 `BroadcastTracker` 维护 `broadcastId -> pending broadcast context`。
- `BeginBroadcast()` 记录 command、attempted、开始时间和待确认上下文。
- `OnAck()` 根据 `broadcastId` 关联 ack，更新 pending context。
- `WaitResult()` 等待 timeout 或完成，填充 `attempted` / `delivered` / `acked` / `timeout` / `elapsedMs`。
- `ExpireOldBroadcasts()` 清理超时后的历史上下文，保留足够窗口用于关联迟到 ack。
- `PauseDetection()` / `ResumeDetection()` / `Reload()` / `Unload()` 返回前到达的 ack 计入返回的 `result.acked`。
- 接口返回后才到达的 ack 计入 `drainAckCorrelated`，不再修改已经返回的 `HostGuardAmsiBroadcastResult`，同时写入 `AdapterDiagRingBuffer` 说明 late ack。

重要约束：

- `PauseDetection()` 失败时，`policyEnabled=false` 仍应保存。
- 已加载 DLL 可能仍检测，需要审计 failed/timeout。
- 本阶段只保证对广播可达的已加载 DLL 发出 pause/resume。
- 本阶段不处理策略关闭后新启动的 PowerShell；如果测试环境新进程仍加载 DLL，属于当前阶段已知限制，不能作为本阶段失败。

## 15. Reload / Unload 接口

规则更新：

```cpp
adapter.UpdateRules(allRulesJson, amsiRulesJson, version, hash, error);
HostGuardAmsiBroadcastResult result;
adapter.Reload(3000, result);
```

卸载：

```cpp
HostGuardAmsiBroadcastResult result;
adapter.Unload(3000, result);
```

语义：

- `Reload()` 广播失败不回滚规则快照。
- `Unload()` best effort。
- HostGuard 根据 result 决定是否重试、告警、审计。
- `Reload()` / `Unload()` 与 pause/resume 一样必须生成 `broadcastId`。
- 如果 DLL 对 reload/unload 产生 status 或 drain ack，新协议必须回带 `broadcastId`；无法关联的 ack 只能作为兼容观测，不计入精确 `acked`。

## 16. 失败模式

规则未就绪：

- 推荐 `Start()` 前强制要求 `UpdateRules()` 成功。
- 如果允许 rule pipe 先启动，`GET_RULES` 必须返回 `RULES_NOT_READY`，不能返回空 JSON 伪装成功。

callback 未设置：

- 建议 `Start()` 失败，要求 HostGuard 明确设置 callback。
- 如果业务选择允许未设置 callback，则 detection/DLL log/status 只能计数丢弃，必须明确写入状态。

pipe 创建失败：

- `Start()` 返回 false。
- 已创建 pipe 全部关闭。
- 状态进入 `Faulted`。

Reload 广播失败：

- 不回滚规则快照。
- 只记录 `HostGuardAmsiBroadcastResult`。
- HostGuard 决定是否再次广播。

Pause 广播失败：

- `policyEnabled=false` 仍应保存。
- 已加载 DLL 可能仍检测，需要审计 failed/timeout。
- 本阶段不处理新进程控制；pause 广播失败只表示已加载 DLL 中存在未确认 pause 的实例，不能推导新进程策略状态。

Stop 超时：

- 记录 `lastError`。
- 标记丢弃/未处理消息计数。
- 不再触发 callback。

## 17. 与现有模块关系

可复用：

- `AmsiIpcHost`
- `AmsiIpcHostConfig`
- `AmsiIpcHostAdapters`
- `IAmsiRuleProvider`
- event sink 注入接口
- control status sink 注入接口
- broadcaster reload / unload / pause / resume

不建议 HostGuard 直接持有：

- `RuleServer`
- `NamedPipeServerPool`
- `AmsiRuleChannel`

这些应封装在 adapter 内。

## 18. 最小落地顺序

1. 新增 `HostGuardRuleSnapshot` 和 `HostGuardRuleProvider`，支持内存规则响应。
2. 新增 `HostGuardEventSink`，读取 event pipe raw payload，并按 `Detection` / `DiagnosticLog` / `DrainAck` / `Unknown` 分类。
3. 新增 detection event queue 和 DLL diagnostic log queue，确保 DLL 日志背压不影响检测事件。
4. 新增 `HostGuardControlStatusSink`，把 raw status 投递到 adapter status queue。
5. 新增 detection/status/DLL diagnostic log 三类独立 forwarder thread，从分类队列取消息并调用 HostGuard callback。
6. 新增 `AdapterDiagRingBuffer` 和可选 `AdapterDiagCallback`，承载 adapter 自身诊断。
7. 新增 `BroadcastTracker`，维护 `broadcastId`、pending context、ack 关联和 late ack 诊断。
8. 新增 control pipe security 校验，`failStartIfPipeSecurityInvalid=true` 时失败即回滚。
9. 新增 `HostGuardAmsiIpcAdapter`，组合 provider/sink/`AmsiIpcHost`。
10. 实现生命周期状态机。
11. 接入 `UpdateRules` / `SetDetectionEnabled` / `Reload` / `PauseDetection` / `ResumeDetection` / `Unload`。
12. 补测试。

## 19. 必测用例

生命周期测试：

- `Init()` 重复调用。
- `Start()` 重复调用。
- `Start()` 失败回滚。
- 未 `Start()` 时调用 `Stop()`。
- `Running` 时调用 `Stop()`。
- `Stop()` 后不再触发 callback。
- 析构时自动 `Stop()`。
- `Stop()` 等待 in-flight callback 返回。
- `Stop()` 返回后销毁 callback 捕获对象不崩溃。
- callback 内同步调用 `Stop()` 的场景应被文档禁止；测试可用异步投递验证正确用法。

并发测试：

- `UpdateRules()` 与 `GET_RULES` 并发。
- `Reload()` 与 `UpdateRules()` 并发。
- `Stop()` 与 event/status 接收并发，覆盖 event pipe payload 分类尚未完成的场景。
- `PauseDetection()` / `ResumeDetection()` 与 `Stop()` 并发。

策略测试：

- `policyEnabled=false` 时，只验证已加载 DLL 的 pause 行为。
- 策略关闭后新启动 PowerShell 是否加载 DLL 不作为本阶段测试目标。
- `policyEnabled=true` 后，只验证仍存活已加载 DLL 的 resume 行为。
- pause/resume best-effort result 正确。

队列/背压测试：

- detection event 队列满时按配置处理并计数。
- detection event 队列同时受条数和字节预算限制。
- DLL diagnostic log 队列满时可丢弃并计数。
- DLL diagnostic log 队列同时受条数和字节预算限制。
- status 队列同时受条数和字节预算限制。
- DLL diagnostic log 风暴不能阻塞 detection event 接收。
- detection event 队列满时验证 `detectionEnqueueTimeoutMs` 后丢弃、计数并进入 degraded。
- status 队列满时保留关键状态或进入 degraded。
- detection/status/DLL log 任一 callback 阻塞时不能造成其他类别队头阻塞。
- `Stop()` drain 超时行为。

event pipe 分类测试：

- `cat == "Detection"` 进入 detection event callback。
- `cat == "diag"` 或 `sensor == "RaspLog"` 进入 DLL diagnostic log callback。
- `cat == "drain-ack"` 不进入 detection event callback。
- 携带 `broadcastId` 的 `drain-ack` 能关联对应 broadcast result。
- 未携带 `broadcastId` 的旧协议 `drain-ack` 只能计入 uncorrelated ack。
- `cat == "drain-ack"` 且 `sensor == "RaspLog"` 时必须归类为 `DrainAck`，不能归类为 DLL diagnostic log。
- 非法 JSON / 未知 `cat` 进入 unknown 计数，不污染安全事件队列。

broadcast tracker 测试：

- `BeginBroadcast()` 后返回前到达 ack 计入 `result.acked`。
- 返回后迟到 ack 计入 correlated late ack，不修改已返回 result。
- 未知 `broadcastId` ack 计入 uncorrelated。
- `ExpireOldBroadcasts()` 清理历史上下文后，迟到 ack 不再影响已完成 result。

安全测试：

- 超大 event JSON。
- 超大 status JSON。
- 队列总字节预算耗尽。
- 非法 command。
- 空规则。
- 非法 JSON。
- pipe 权限配置失败。
- control pipe 禁止 Everyone / Authenticated Users 写入。
- 低权限用户不能连接 control pipe 执行 reload / unload / pause / resume。

## 20. 后续可选优化

如果后续 HostGuard 也需要复用 demo 中的规则组装和 Lua bytecode 编译，可再拆独立接口：

```cpp
class ILuaRuleCompiler {
public:
    virtual bool CompileSourceToBytecode(
        const std::string& source,
        const std::string& chunkName,
        std::vector<uint8_t>& out,
        std::string& error) = 0;
};
```

或者：

```cpp
class IRuleAssembler {
public:
    virtual bool BuildAssembledRulesJson(
        const std::string& rulesPath,
        std::string& outJson,
        std::string& error) = 0;
};
```

本批迁移建议先保持通信层最小化，不把规则读取、编译和策略业务混入 IPC adapter。
