# DetectPsByAmsi / RASP AMSI EDR 迁移边界规划

## 1. 总体迁移原则

当前工程应拆成三个清晰边界：AMSI Provider DLL、scanner-core / rule-runtime 公共扫描能力、EDR 检测进程 adapter。迁移目标不是把现有 `rasp_sentry_native.exe` 原样搬进 EDR，而是把规则、配置、事件、日志、生命周期控制分别接入 EDR 的现有能力。

### 1.1 应迁移到 EDR 检测进程的能力

| 能力 | 目标归属 | 说明 |
|---|---|---|
| 规则服务、规则热更新、规则版本管理 | EDR 规则中心 | 替代 `rasp_sentry_native::RuleServer` |
| 配置监听、策略下发 | EDR 配置中心 | 替代 `ConfigWatcher` 文件监听和裸 pipe 广播 |
| 检测事件接收、聚合、转发 | EDR 事件总线 | 替代 `EventCollector` 的 JSONL pipe 模式 |
| 日志落盘、日志级别、采样 | EDR 日志系统 | DLL 和 scanner-core 不直接落盘 |
| 模块启动、停止、升级、回滚 | EDR 模块管理 / 升级系统 | 替代 `AmsiStagingWatcher` 的独立 staging 逻辑 |
| Provider 控制面服务端 | EDR control-plane adapter | 向 DLL 提供规则、reload、shutdown、状态确认 |

### 1.2 应保留在 AMSI Provider DLL 的能力

| 能力 | 当前文件 / 类 | 保留原因 |
|---|---|---|
| COM / AMSI Provider 导出 | `src/rasp_mod_amsi/src/rasp_mod_amsi.cpp` | 由 Windows AMSI 框架加载 |
| `DllGetClassObject` / class factory | `rasp_mod_amsi.cpp` / `amsi_provider.cpp` | AMSI Provider 必需边界 |
| `IAntimalwareProvider::Scan()` | `src/rasp_mod_amsi/src/amsi_provider.cpp` | 宿主进程内同步调用点 |
| `IAmsiStream` 提取 | `amsi_provider.cpp` | AMSI COM 强绑定 |
| `EngineRuntime` / `ScanGuard` / inert / drain | `engine_runtime.h/.cpp` | 宿主内生命周期和并发治理 |
| AMSI_RESULT 决策返回 | `amsi_provider.cpp` | Provider 的最终职责 |
| Provider 侧 transport adapter | 后续新增 | 只做本地缓存规则、异步事件、控制命令接收 |

### 1.3 应沉淀为 scanner-core / rule-runtime 的能力

| 能力 | 目标模块 | 当前来源 |
|---|---|---|
| 输入归一化、UTF-16/NUL/Base64/4KB 有界视图 | `normalization` / `scanner-core` | `script_input_normalizer.*` |
| Session Context 有界聚合 | `session-context` | Phase 3 Batch 2 新增 |
| ScanBudget / ScanDeadline / ScanExecutionContext | `scanner-core` | `rasp_scan_budget.h` |
| 规则快照读取、扫描编排、决策生成 | `scanner-core` | `amsi_rule_engine.cpp::Evaluate` |
| 规则结构、规则 JSON 解析 | `rule-runtime` | `rasp_rule_base.h` / `rasp_sentry_base.cpp` |
| Lua / PCRE2 执行 | `rule-runtime` | `rasp_lua_engine.*` |
| 轻量事件结构 | `scanner-core` / telemetry boundary | `RaspEvalResult` / `AsyncEvent` |

### 1.4 不应继续留在 DLL 中的代码

- 规则中心管理、规则文件监听、规则组装服务端。
- 复杂日志落盘、JSONL 文件写入。
- 数据库 schema、SQL、持久化字段决策。
- 长时间阻塞 IPC、同步重连 EDR、远程配置拉取。
- 大量后台线程、升级 watcher、staging 文件替换逻辑。
- EDR 全局生命周期和权限模型。

### 1.5 不应直接写死到 EDR 平台中的代码

- Lua / PCRE2 规则执行细节。
- AMSI COM / `IAmsiStream` 细节。
- 输入归一化和 session-context 的具体算法。
- Provider 内部 `EngineRuntime` 锁和状态机。
- 旧 `rasp_sentry_*` pipe 协议。

### 1.6 防止迁移后形成新强耦合

- `scanner-core` 只依赖抽象接口，不依赖 AMSI / EDR / pipe / DB。
- `rule-runtime` 只负责规则解析、编译、执行，不发送事件。
- `provider-adapter` 只把 AMSI 输入转换为 `ScriptScanInput`，不承载 EDR 业务。
- `edr-adapter` 只实现规则、配置、事件、日志接口，不访问 Provider runtime 内部锁。
- `compatibility-layer` 只承载旧协议兼容，不承载新业务语义，并必须有删除条件。

## 2. 目标模块划分

| 模块 | 职责 | 输入 | 输出 | 禁止依赖项 |
|---|---|---|---|---|
| `provider-adapter` | AMSI COM 注册、`IAmsiStream` 提取、AMSI_RESULT 返回 | `IAmsiStream*`、AMSI session | `ScriptScanInput`、`ScriptScanResult` / `DetectionAction` | DB、EDR SDK、规则中心管理 |
| `scanner-core` | 编排归一化、session context、预算、规则快照扫描 | `ScriptScanInput`、`ScriptScanContext` | `ScriptScanResult` | AMSI COM、named pipe、EDR SDK、DB |
| `rule-runtime` | 规则 JSON、Lua、PCRE2、RuleSnapshot | 规则 JSON / compiled snapshot | `RuleEvalResult` | AMSI、EDR、pipe、event sink |
| `normalization` | UTF-8/UTF-16/NUL/Base64/4KB 视图 | raw bytes | normalized body + metadata | 规则执行、EDR、pipe |
| `session-context` | 有界 session 聚合、LRU、TTL、内存上限 | `ScriptSessionKey` + normalized chunk | bounded session view | AMSI COM 指针、Lua state、RuleSnapshot 指针 |
| `control-plane-adapter` | 获取规则快照、接收 reload/unload/shutdown | EDR 配置/规则事件 | immutable snapshot / command | Scan 热路径阻塞 |
| `telemetry-adapter` | detection / telemetry 进入 EDR event bus | `DetectionEventLite` | EDR event | 规则执行、AMSI COM |
| `edr-module-adapter` | EDR 进程内模块生命周期、线程池、权限模型 | EDR SDK | control-plane / event sink 实现 | AMSI COM |
| `compatibility-layer` | 旧 sentry pipe 兼容 | old pipe protocol | 新 adapter 调用 | 新业务语义、长期保留 |

## 3. rasp_sentry_native.exe 功能迁移边界

| 当前功能 | 当前文件 | 迁移后归属 | 处理结论 | 理由 |
|---|---|---|---|---|
| `RuleServer` | `src/rasp_sentry_native/src/rule_server.cpp` | B. EDR 规则中心 / G. 临时兼容 | 改造成 legacy rule pipe adapter，最终废弃 | 规则服务属于 EDR 规则中心，不应是独立 exe |
| `EventCollector` | `src/rasp_sentry_native/src/event_collector.cpp` | C. EDR 事件总线 / E. telemetry adapter | 迁移到 EDR event bus，legacy JSONL 仅过渡 | 事件落盘和聚合应由 EDR 管理 |
| `ConfigWatcher` | `src/rasp_sentry_native/src/config_watcher.cpp` | A. EDR 配置中心 | 废弃文件监听，改为 EDR 配置订阅 | 配置源应统一 |
| `AmsiStagingWatcher` | `src/rasp_sentry_native/src/amsi_staging_watcher.cpp` | F. 废弃或重构 | 纳入 EDR 升级系统 | DLL staging/update 不应由 sentry 私自管理 |
| 日志落盘 | `src/rasp_sentry_native/src/sentry_log.cpp` | D. EDR 日志系统 | 迁移到 EDR logger，短期兼容 | 统一日志级别、采样、路径和权限 |
| 命名管道通信 | `rule_server.cpp` / `event_collector.cpp` / `config_watcher.cpp` | G. 临时兼容保留 | pipe 仅作为 transport | 旧协议不能继续承载业务边界 |
| 规则组装 | `rule_server.cpp` | B. EDR 规则中心 + C. rule-runtime | 规则源归 EDR，编译归 rule-runtime | 避免 DLL 和 EDR 各自解析不同语义 |
| reload / unload 广播 | `config_watcher.cpp` / `amsi_staging_watcher.cpp` | A. EDR 配置中心 + E. provider adapter | 改为版本化 control message | 替代裸 0x01 / 0x02 信号 |
| drain-ack / 状态确认 | `event_collector.cpp` | C. EDR 事件总线 / control-plane | 改为结构化 provider status | 不应混在 detection JSONL |

## 4. AMSI Provider DLL 迁移边界

### 4.1 DLL 应保留职责

- COM / AMSI Provider 注册。
- `DllGetClassObject`。
- `IAntimalwareProvider::Scan()`。
- `IAmsiStream` 内容、contentName、appName、session 提取。
- `EngineRuntime`、`ScanGuard`、`ReloadGuard`、inert、bounded shutdown drain。
- `ScriptInputNormalizer` 调用，后续迁移为 scanner-core 调用。
- `AmsiSessionContextCache` 调用，按 scanner-core 边界实现。
- 本地规则快照读取，不在 Scan 热路径远程拉取。
- 调用 scanner-core / rule-runtime 完成检测。
- 将 `ScriptScanResult.action/status` 按 fail policy 转换为 `AMSI_RESULT_DETECTED / NOT_DETECTED`。

### 4.2 DLL 禁止职责

- 长时间阻塞 IPC。
- 规则中心管理。
- 配置中心管理。
- 复杂日志落盘。
- 数据库写入。
- EDR 全局状态管理。
- 大量后台线程。
- 网络通信。
- 在 Scan 热路径等待 EDR 进程、pipe、日志、磁盘、远程配置。

## 5. scanner-core 接口契约

### 5.1 数据结构建议

```cpp
struct ScriptSessionKey {
    uint32_t pid;
    uint32_t tid;
    uint64_t amsiSession;
    std::string contentNameHash;
    SessionKeyConfidence confidence;
};

struct ScriptScanInput {
    const uint8_t* bytes;
    size_t length;
    std::string contentName;
    std::string appName;
    std::string source;
    ScriptSessionKey sessionKey;
};

struct ScriptScanContext {
    ScanBudget budget;
    uint64_t timestampMs;
    std::string policyId;
    bool failOpenAllowed;
};

enum class SessionKeyConfidence {
    Strong,
    Medium,
    Weak,
    None
};

enum class DetectionAction {
    Allow,
    Audit,
    Block
};

enum class ScanStatus {
    Ok,
    Timeout,
    EngineError,
    NoSnapshot,
    Inert,
    Faulted
};

struct DetectionEventLite {
    std::string ruleId;
    std::string severity;
    std::string decision;
    std::string sampleHash;
    size_t sampleLen;
    bool truncated;
    bool timedOut;
};

struct ScriptScanResult {
    DetectionAction action;
    ScanStatus status;
    std::vector<DetectionEventLite> events;
    std::string reason;
    bool engineHealthy;
};
```

`Timeout`、`EngineError`、`NoSnapshot`、`Inert`、`Faulted` 是扫描状态，不是最终安全动作。AMSI Provider 最终返回 `AMSI_RESULT_DETECTED / NOT_DETECTED` 时，必须由 fail policy 将 `ScanStatus` 映射为 `DetectionAction`，禁止在调用点把 timeout 隐式等同于 allow 或 block。

### 5.2 错误语义与降级语义

```cpp
enum class RuleProviderStatus {
    Ok,
    NotReady,
    StaleSnapshot,
    Disconnected,
    Faulted
};

enum class SubmitStatus {
    Submitted,
    DroppedQueueFull,
    DroppedStopping,
    SinkUnavailable,
    InvalidEvent
};
```

| 状态 | 语义 | 建议降级 |
|---|---|---|
| `RuleProviderStatus::Ok` | 当前 snapshot 可用 | 正常扫描 |
| `RuleProviderStatus::NotReady` | 初始化尚未完成 | 按启动期 fail policy，通常 audit/allow |
| `RuleProviderStatus::StaleSnapshot` | 使用旧 snapshot，超过推荐刷新时间但未超过硬 TTL | 继续扫描并记录 telemetry |
| `RuleProviderStatus::Disconnected` | EDR control-plane 不可用 | 使用 last snapshot；超过 TTL 后进入 inert 或 strict policy |
| `RuleProviderStatus::Faulted` | 规则提供方内部不可信 | 不继续复杂检测，进入 fault/inert 策略 |
| `SubmitStatus::Submitted` | 事件已进入本地队列或 adapter | 正常 |
| `SubmitStatus::DroppedQueueFull` | 队列满导致丢弃 | 增加 dropped_count |
| `SubmitStatus::DroppedStopping` | shutdown/inert 中拒绝新事件 | 不阻塞 Scan |
| `SubmitStatus::SinkUnavailable` | EDR event sink 不可用 | backoff + dropped_count |
| `SubmitStatus::InvalidEvent` | 事件字段非法或超过上限 | 丢弃并记录本地计数 |

`CurrentSnapshot()` 不应只用 `nullptr` 表达所有失败。后续接口实现应返回 snapshot + `RuleProviderStatus`，或通过独立状态查询接口暴露原因，使 fail-open / fail-close / enter-inert 策略可精确落地。

### 5.3 SessionKey 置信度与降级规则

| `SessionKeyConfidence` | 适用条件 | 聚合策略 |
|---|---|---|
| `Strong` | AMSI session 可用，pid/contentName 稳定 | 允许正常 4KB session 聚合 |
| `Medium` | 无 AMSI session，但 pid/tid/contentName 稳定 | 短 TTL 聚合，严格内存上限 |
| `Weak` | 只能得到 pid/tid 或 contentName 弱关联 | 谨慎聚合或仅同线程短窗口聚合 |
| `None` | 无可靠 key | 降级为单 chunk 检测 |

session-context 禁止在 key 置信度不足时跨请求长期聚合，避免不同脚本上下文污染导致误报或漏报。

### 5.4 接口契约表

| 接口 / 类型 | 所属模块 | 调用方 | 实现方 / 构造方 | 是否允许阻塞 |
|---|---|---|---|---|
| `ScriptScanInput` | `scanner-core` | provider adapter | caller 构造 | N/A |
| `ScriptSessionKey` | `scanner-core/session-context` | provider adapter / scanner-core | provider adapter 构造 | N/A |
| `ScriptScanContext` | `scanner-core` | provider adapter | config adapter 填充 | 不允许远程拉取 |
| `ScriptScanResult` | `scanner-core` | provider adapter 消费 | scanner-core 生成 | N/A |
| `DetectionEventLite` | telemetry boundary | scanner-core / provider | scanner-core 生成 | N/A |
| `IRuleProvider` | scanner-core boundary | scanner-core | DLL adapter / EDR adapter | Scan 热路径不允许阻塞 |
| `IEventSink` | telemetry boundary | scanner-core / provider | `AsyncEventSink` / EDR adapter | `TrySubmit` 不允许阻塞 |
| `IConfigProvider` | config boundary | scanner-core | EDR config adapter | Scan 中不允许远程拉取 |
| `IClock` | utility boundary | scanner-core | platform adapter | 不阻塞 |

### 5.5 接口定义方向

```cpp
class IRuleProvider {
public:
    virtual RuleProviderStatus CurrentSnapshot(std::shared_ptr<const RuleSnapshot>& out) = 0;
    virtual RuleProviderStatus Status() const = 0;
};

class IEventSink {
public:
    virtual SubmitStatus TrySubmit(const DetectionEventLite& event) = 0;
};

class IConfigProvider {
public:
    virtual ScanBudget CurrentBudget() const = 0;
    virtual bool FailOpenAllowed() const = 0;
};

class IClock {
public:
    virtual uint64_t NowMs() const = 0;
};
```

硬约束：`scanner-core` 只能依赖接口，不能依赖 EDR SDK / AMSI COM / pipe / DB。

## 6. 控制面迁移设计

### 6.1 当前控制面问题

当前 Provider 与 `rasp_sentry_native.exe` 通过 named pipe 完成获取规则、reload、unload、发送事件、drain ack。该模型的问题是业务语义和 transport 强耦合，且 pipe 名称、JSONL、裸信号混在一起。

### 6.2 目标控制面

```text
AMSI Provider DLL
  -> ProviderControlClient
  -> transport(named pipe / ALPC / shared memory)
  -> EDR Detection Process control-plane adapter
  -> EDR config center / rule center / module manager
```

### 6.3 关键设计

| 问题 | 设计 |
|---|---|
| Provider 如何获取规则快照 | 启动或 reload 时从 EDR control-plane 获取版本化 snapshot；Scan 热路径只读本地缓存 |
| EDR 如何下发规则 | EDR 规则中心生成规则版本，control-plane adapter 发布 |
| 是否继续使用 pipe | 第一阶段继续 named pipe，作为 transport 降低迁移风险 |
| 是否保留旧协议 | 不保留旧业务语义；通过 `LegacySentryPipeAdapter` 映射 |
| reload 如何表达 | `ControlMessage{type: Reload, version, reason}` |
| unload / shutdown 如何表达 | `ControlMessage{type: EnterInert/Shutdown, deadlineMs}` |
| drain ack 如何表达 | `ProviderStatus{state, activeScans, drained, timeout}` |
| 如何避免 DLL 阻塞 | reload 后台构建，publish 短窗口；Scan 只读 snapshot |
| 如何平滑迁移 | compatibility-layer 同时支持旧 sentry pipe 和新 EDR control-plane |

## 7. 事件与日志迁移设计

| 项目 | 迁移设计 |
|---|---|
| DetectionEvent 进入 EDR | `AsyncEventQueue` worker 调用 EDR telemetry adapter |
| `AsyncEventQueue` 是否保留 | 保留，作为 Provider 内非阻塞热路径保护 |
| `SendDetectionEventSyncWorkerOnly` | 改为 EDR event sink 的 worker-only 实现细节 |
| 哪些字段暂不落库 | normalizer metadata、session debug、decoded flags 继续仅内存/调试/测试 |
| Scan 热路径日志 | 禁止写 pipe、写 DB、写磁盘、同步 EDR event bus |
| EDR 不可用 | queue backoff；满则按优先级 drop；保留 dropped_count |
| timeout / dropped telemetry | 聚合后异步发送；必要时 OutputDebugString 采样 |

事件对象必须自包含，不持有 `IAmsiStream*`、`RuleSnapshot*`、`std::string_view` 指向 scan 栈、Lua state、PCRE2 match data。

## 8. 生命周期与线程模型迁移

| 生命周期 | DLL 负责 | EDR 检测进程负责 | scanner-core 负责 |
|---|---|---|---|
| DLL 加载 / 卸载 | 极简 `DllMain`、惰性初始化、inert | 不负责 | 不负责 |
| EDR 进程启动 / 停止 | 感知断连、backoff、降级 | 模块启动、规则中心、event bus | 不负责 |
| 规则 reload | `BuildNextSnapshot -> TryEnterReload -> PublishSnapshot` | 生成和发布规则版本 | 编译/验证 snapshot |
| provider inert mode | 快速拒绝复杂 scan，不新建复杂线程 | 发 control command | 不负责 |
| shutdown drain | `BeginShutdown()` 有界等待 | 等待 provider status | 不负责 |
| async event worker | 队列、短 flush、stop | event bus 消费 | 不负责 |
| session cache 清理 | 调用 cache cleanup / close | 不负责 | 提供 LRU / TTL 逻辑 |
| scan budget 超时 | 传入配置、记录结果 | 下发预算策略 | 执行预算检查 |
| EDR 重启 | 使用旧 snapshot / inert / policy 降级 | 恢复后重新发布 | 不负责 |

## 9. 权限与安全边界

### 9.1 IPC 权限

- 继续使用 named pipe 时，必须设置 ACL。
- 允许主体建议：`SYSTEM`、EDR service SID、Administrators；必要时要求 High IL。
- 普通用户不得伪造 reload / unload / rule snapshot。
- EDR 接收 Provider 事件时应校验 client PID、SID、integrity level、签名路径。
- Provider 连接 EDR pipe 时应校验服务端身份，避免低权限进程伪装 EDR。

### 9.1.1 服务端身份校验建议

Provider 连接 EDR control-plane transport 后，至少应采用以下可落地校验链路之一，不能只依赖 pipe 名称：

1. Pipe ACL 限制为 EDR service SID / `SYSTEM` / Administrators，普通用户无创建和写入权限。
2. Provider 连接后通过 `GetNamedPipeServerProcessId` 获取服务端 PID。
3. 打开服务端进程 token，校验 SID、integrity level、session id。
4. 校验服务端镜像路径位于 EDR 安装目录，并校验签名或产品证书。
5. 校验 control message 的 protocol version、nonce、长度上限和方向字段。
6. 任一校验失败时，不进入同步重试；记录 telemetry，进入 backoff，并按断连策略使用 last snapshot / inert / strict policy。

### 9.2 EDR 断连策略

| 策略 | 行为 | 适用场景 |
|---|---|---|
| `use_last_snapshot` | 使用最后一次有效规则快照继续扫描 | 默认推荐 |
| `enter_inert` | 不执行复杂检测，快速返回 | EDR 长时间不可用 |
| `strict_block_or_audit` | 断连/超时转阻断或强审计 | 关键服务器 / 高安全策略 |

建议参数：

```text
last_snapshot_ttl_seconds = 300 / 600 / configurable
edr_disconnect_backoff_ms = 100 -> 5000
control_plane_deadline_ms = bounded
```

断连时 Provider 禁止在 Scan 热路径同步等待 EDR 恢复。

### 9.3 旧 pipe 处理

- `rasp_sentry_rules`、`rasp_sentry_events`、`rasp_sentry_config` 进入 compatibility-layer。
- 旧 pipe 不允许新增业务语义。
- 新 control-plane message 必须版本化、长度有界、字段可校验。

## 10. 分阶段迁移路线

| 阶段 | 目标 | 主要修改文件 | 风险 | 回滚方式 | 验收标准 |
|---|---|---|---|---|---|
| Phase A | 迁移规划与接口抽象 | `docs/edr_migration_boundary_plan.md` | 边界不清导致返工 | 文档回滚 | 模块边界、接口契约、文件归属、门禁明确 |
| Phase A1 | Phase 3 Batch 2 session-context | 新增 `ScriptSessionContextCache / AmsiSessionContextCache` | 分段聚合污染上下文 | feature flag 关闭 session 聚合 | 4KB 上限、TTL、LRU、key confidence 测试通过 |
| Phase B0 | `RaspSentryBase` 职责拆分准备 | `rasp_sentry_base.*`、新增 boundary interfaces | 上帝类继续拖住抽离 | 保留旧 `RaspSentryBase` 入口 | RuleControl/EventSubmit/DiagLogger/LegacyPipeTransport 边界形成 |
| Phase B | 抽离 scanner-core | `script_input_normalizer.*`、新增 `scanner_core/*`、部分 `amsi_rule_engine.cpp` | 行为变化 | DLL 继续走旧 `AmsiRuleEngine` | normalizer/session/budget 测试通过 |
| Phase C | 抽离 rule-runtime | `rasp_lua_engine.*`、规则 parser、RuleSnapshot | Lua/PCRE2 生命周期风险 | 保留旧构建路径 | reload/scan 并发测试通过 |
| Phase D | 抽离 sentry 功能为 EDR adapter | 新增 `control_plane_adapter`、legacy pipe adapter | reload 语义漂移 | 回退旧 sentry pipe | reload/unload/drain 状态一致 |
| Phase E | Provider 接入 EDR control-plane，事件进 EDR event bus | `async_event_queue.*`、event sink adapter | 事件丢失 | 回退 JSONL pipe | queue/drop/backoff 指标正确 |
| Phase F | 废弃旧 sentry exe | `rasp_sentry_native/main.cpp` 等 | 兼容环境断裂 | 保留 legacy exe 包 | EDR 完整替代规则/事件/config |
| Phase G | 兼容清理和生产化 | 删除 legacy pipe / watcher | 遗留依赖 | feature flag 恢复 | 无旧 pipe 强依赖，权限审计通过 |

## 11. 风险清单

| 风险 | 影响 | 缓解建议 |
|---|---|---|
| DLL 与 EDR 进程强耦合 | EDR 重启拖死宿主 | DLL 只依赖抽象接口和 cached snapshot |
| Scan 热路径重新阻塞 | PowerShell 卡顿、DoS | 禁止同步 IPC、远程配置、阻塞日志 |
| 规则 reload 语义变化 | 漏报或旧规则丢失 | 保留 `BuildNextSnapshot -> TryEnterReload -> PublishSnapshot` |
| 事件丢失 | 告警缺失 | dropped_count、优先级队列、backoff、聚合 telemetry |
| IPC 权限回退 | 普通用户伪造规则/事件 | ACL + PID/SID/IL 校验 |
| 生命周期双重管理 | deadlock / UAF | DLL 管 runtime，EDR 管 control-plane，scanner-core 无线程所有权 |
| EDR 重启导致 Provider fail-open | 检测窗口 | last snapshot TTL + inert / strict policy |
| 旧 sentry 兼容长期遗留 | 技术债 | compatibility-layer 删除门禁 |
| 数据库字段不匹配 | 事件写入失败 | `DetectionEventLite` 与 EDR schema adapter 分离 |
| 配置中心和规则中心语义漂移 | 规则不一致 | `IRuleProvider` / `IConfigProvider` 契约测试 |

## 12. 当前文件未来归属

| 文件 | 未来归属 | 理由 |
|---|---|---|
| `src/rasp_mod_amsi/src/amsi_provider.cpp` | A. 保留在 AMSI Provider DLL | AMSI COM / `IAmsiStream` 强绑定 |
| `src/rasp_mod_amsi/src/rasp_mod_amsi.cpp` | A. 保留在 AMSI Provider DLL | DLL 入口、COM factory、注册导出 |
| `src/rasp_mod_amsi/src/amsi_rule_engine.cpp` | A + B 逐步拆分 | AMSI adapter 留 DLL；Evaluate/normalization/session 编排抽 scanner-core |
| `src/rasp_mod_amsi/src/engine_runtime.cpp` | A. 保留在 DLL | Provider 宿主内生命周期，不进 EDR |
| `src/rasp_mod_amsi/src/script_input_normalizer.cpp` | B. 抽到 scanner-core | 与 AMSI 无关，可复用 |
| `src/rasp_rule_engine/src/rasp_sentry_base.cpp` | 拆分为 B/C/D/E/G | 当前混合解析、IPC、日志、事件，必须拆 |
| `src/rasp_rule_engine/src/rasp_lua_engine.cpp` | C. rule-runtime | Lua / PCRE2 执行核心 |
| `src/rasp_rule_engine/src/async_event_queue.cpp` | B/E 边界 | 队列通用，发送端适配 EDR telemetry |
| `src/rasp_sentry_native/src/main.cpp` | F. 废弃 | 独立 exe 生命周期迁入 EDR |
| `src/rasp_sentry_native/src/rule_server.cpp` | D/G | 过渡为 `LegacyRulePipeAdapter`，最终由 EDR 规则中心替代 |
| `src/rasp_sentry_native/src/event_collector.cpp` | E/G | 过渡为 legacy collector，最终 EDR event bus |
| `src/rasp_sentry_native/src/config_watcher.cpp` | D/F | 文件监听和广播由 EDR 配置中心替代 |
| `src/rasp_sentry_native/src/amsi_staging_watcher.cpp` | F/G | DLL staging/update 归 EDR 升级系统 |
| `src/rasp_sentry_native/src/pipe_security.cpp` | compatibility-layer | 可复用 ACL，但要升级权限模型 |
| `src/rasp_sentry_native/src/sentry_log.cpp` | D/G | 短期兼容日志，长期 EDR logger |

## 13. Phase 3 Batch 2 代码边界要求

Phase 3 Batch 2 应实现 `ScriptSessionContextCache / AmsiSessionContextCache`，但必须按 scanner-core 组件边界设计。

允许：

- 基于 `ScriptSessionKey` 的有界 session 聚合。
- 每 session 4KB 上限。
- LRU / TTL / 全局内存上限。
- CloseSession / Clear / shutdown cleanup。
- 单元测试覆盖拆分脚本、LRU、TTL、并发、内存上限。

禁止：

- 依赖 `IAmsiStream*`。
- 依赖 `RuleSnapshot*`。
- 依赖 Lua state / PCRE2 runtime 对象。
- 依赖 sentry pipe / EDR SDK / DB。
- 在 Scan 热路径等待清理线程、IPC、EDR、磁盘日志。

## 14. RaspSentryBase 拆分子任务

`src/rasp_rule_engine/src/rasp_sentry_base.cpp` 当前混合规则解析、IPC、日志、事件、生命周期 hook，不适合作为迁移后的公共基类。建议单独立项 `Split RaspSentryBase`。

| 当前职责 | 目标模块 |
|---|---|
| 规则拉取 / reload pipe | `RuleControlClient` / `LegacyPipeTransport` |
| 事件发送 | `EventSubmitClient` / `TelemetryAdapter` |
| 诊断日志 | `DiagLogger` |
| pipe 读写 | `LegacyPipeTransport` |
| JSON 规则解析 | `rule-runtime` |
| 生命周期 hook | provider adapter / runtime hooks |

拆分完成前，`RaspSentryBase` 不应继续扩大职责。

## 15. Compatibility Layer 退出条件

Legacy pipe 兼容层必须有明确删除门禁，避免永久技术债。

Legacy pipe 删除条件：

- EDR control-plane 已稳定下发规则。
- EDR event bus 已稳定接收 detection event。
- reload / unload / drain 状态语义完成替代。
- 所有测试环境不再依赖 `rasp_sentry_native.exe`。
- 灰度环境连续 N 天无 fallback 到 legacy pipe。
- 安装 / 升级脚本不再部署旧 sentry exe。
- 旧 `rasp_sentry_rules/events/config` 协议没有承载新业务语义。

版本门槛：

```text
target_removal_version = <planned product version>
latest_allowed_release = <last release allowed to ship legacy pipe>
```

兼容层新增功能必须同时填写删除条件、目标移除版本和最后允许发布版本。没有版本门槛的 legacy 功能不得进入主干。

## 16. 迁移前置门禁：Scanner-Core 依赖净化

在任何 scanner-core / rule-runtime / session-context 物理抽离之前，必须先通过依赖净化门禁。

### 16.1 适用范围

- `src/scanner_core`
- `src/rule_runtime`
- `src/session_context`
- `src/rasp_rule_engine` 中计划沉淀为公共库的文件

### 16.2 禁止依赖

- AMSI / COM：`amsi.h`、`objbase.h`、`combaseapi.h`、`IAmsiStream`、`IAntimalwareProvider`。
- Windows IPC：`CreateNamedPipe`、`ConnectNamedPipe`、`TransactNamedPipe`、控制面 `ReadFile` / `WriteFile`。
- 旧 sentry pipe 名称：`rasp_sentry_rules`、`rasp_sentry_events`、`rasp_sentry_config`。
- EDR SDK：任何 EDR 平台专有头文件、命名空间、事件总线 SDK。
- 数据库 schema：表名、落库字段、SQL、JSONL 持久化格式。
- Provider 生命周期：`DllMain`、`DllGetClassObject`、`EngineRuntime` 内部锁、AMSI unload 逻辑。

### 16.3 允许依赖

- C++ 标准库。
- Lua / PCRE2 runtime 封装。
- `ScanBudget` / `ScanDeadline`。
- `ScriptInputNormalizer`。
- `ScriptSessionKey`。
- 抽象接口：`IRuleProvider`、`IEventSink`、`IConfigProvider`、`IClock`。
- 平台无关数据结构：`ScriptScanInput`、`ScriptScanResult`、`DetectionEventLite`。

### 16.4 自动化检查建议

后续新增脚本：

- `scripts/check_scanner_core_boundaries.ps1`

检查内容：

- 扫描公共核心目录中的 forbidden include。
- 扫描旧 sentry pipe 名称。
- 扫描 Windows IPC API。
- 扫描 EDR SDK namespace / include。
- 扫描数据库表名和 SQL 关键路径。
- 检查 `scanner-core` 是否反向 include provider adapter。

## 17. Code Review Gate / 代码审查门禁

后续所有 PR 涉及迁移、scanner-core、rule-runtime、provider adapter、EDR adapter、compatibility-layer、session-context 时，必须按以下门禁审查。

1. 新增 scanner-core 代码不得 include AMSI / COM / EDR SDK / pipe / DB 头文件。
2. 新增 rule-runtime 代码不得调用 event sink，不得直接发送事件。
3. 新增 provider adapter 代码不得写数据库或直接落盘日志。
4. 新增 EDR adapter 不得访问 `EngineRuntime` 内部锁，不得反向控制 Provider 私有状态。
5. 新增 compatibility-layer 功能必须标注删除条件和退出门禁。
6. 新增 session-context 代码不得依赖 `IAmsiStream*`、`RuleSnapshot*`、Lua state、PCRE2 match data。
7. Scan 热路径不得新增任何同步 IPC、远程配置拉取、阻塞日志、磁盘写入、数据库写入。

该章节是后续 PR review 的判定依据。违反任一条，应视为架构边界回归。

## 18. 最终建议

- 不建议现在立即整体迁入 EDR。
- 建议先完成本迁移边界文档，再进入 Phase 3 Batch 2。
- Phase 3 Batch 2 应实现 session-context，但按 scanner-core 边界编写，避免后续返工。
- 优先抽象 `ScriptScanInput`、`ScriptScanResult`、`IRuleProvider`、`IEventSink`、`IConfigProvider`、`RuleSnapshot`。
- 暂时不要改 `DllMain`、COM 注册、`IAntimalwareProvider::Scan()` 返回语义、Phase 2 `EngineRuntime` 状态机。
- 下一步最小可执行任务：基于本门禁开发 Phase 3 Batch 2，并先写 `session-context` 测试。
