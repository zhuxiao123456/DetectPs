# AMSI IPC Host 通信模块抽离设计

本文档基于当前 `codex` 分支最新代码，重新审视 `rasp_sentry.exe` 中命名管道通信能力的剥离方式。目标是把当前 EXE 侧通信能力抽成可被 HostGuard 复用的独立模块，后续 HostGuard 只调用接口，不复制 `rasp_sentry_native` 内部实现。

本轮只做方案冻结，不改代码。

## 1. 当前架构结论

当前主线已经完成旧 `rasp_sentry_*` 管道到 `amsi_detect_*` 管道的替换，并新增了控制状态通道：

| 通道 | 当前 pipe | 方向 | 当前实现 |
|---|---|---|---|
| 规则拉取 | `\\.\pipe\amsi_detect_rules` | DLL -> EXE | `RuleServer` |
| 检测/诊断事件 | `\\.\pipe\amsi_detect_events` | DLL -> EXE | `EventCollector` |
| 规则加载状态 | `\\.\pipe\amsi_detect_control_status` | DLL -> EXE | `ControlStatusCollector` |
| reload/unload 控制 | `\\.\pipe\amsi_detect_config` | EXE -> DLL listener | `ConfigWatcher` / `AmsiStagingWatcher` 广播，DLL 侧 `ConfigPipeThreadProc` 监听 |

当前可以开始抽离 EXE 侧 IPC，但不建议一次性搬迁 `RuleServer` / `EventCollector` / `ConfigWatcher` 的全部职责。正确路线是先抽 transport 与 channel seam，再逐步把业务逻辑挂到接口后面。

## 2. 当前代码事实

### 2.1 `RuleServer`

文件：

- `src/rasp_sentry_native/include/rule_server.h`
- `src/rasp_sentry_native/src/rule_server.cpp`

当前职责：

- 创建 8 个 `amsi_detect_rules` pipe server worker。
- 接收 `GET_RULES` / `GET_ALL_RULES`。
- 从 `rasp_rules.json` 构造 assembled JSON。
- inline global libraries。
- inline / 编译 Lua script body。
- 过滤 `AmsiProvider` 规则。
- 维护 `m_cachedAssembled` / `m_cachedAmsiRules`。

需要剥离的通信职责：

- `CreateNamedPipeW`
- `ConnectNamedPipe`
- `ReadFile` 请求
- `WriteFile` 响应
- worker pool 生命周期

不应先剥离的业务职责：

- 规则 JSON 构造。
- Lua source / bytecode 处理。
- 规则缓存策略。
- 规则文件读取。

### 2.2 `EventCollector`

文件：

- `src/rasp_sentry_native/include/event_collector.h`
- `src/rasp_sentry_native/src/event_collector.cpp`

当前职责：

- 创建 16 个 `amsi_detect_events` pipe server worker。
- 接收 DLL 发送的 DetectionEvent / DiagLog / drain-ack JSON line。
- 追加写入 `rasp-events-YYYY-MM-DD.jsonl`。
- 识别 drain-ack 并放入 `DrainAckQueue`，供 `AmsiStagingWatcher` 等待 DLL drain。

需要剥离的通信职责：

- events pipe server worker。
- 读取单条 JSON line。
- 把读取结果交给事件 sink。

不应先剥离的业务职责：

- JSONL 落盘策略。
- drain-ack 队列语义。
- 日志文件路径和滚动策略。

### 2.3 `ControlStatusCollector`

文件：

- `src/rasp_sentry_native/include/control_status_collector.h`
- `src/rasp_sentry_native/src/control_status_collector.cpp`

当前职责：

- 创建 2 个 `amsi_detect_control_status` pipe server worker。
- 接收 DLL 上报的 `RULE_LOAD_RESULT`。
- 追加写入 `rasp-control-status-YYYY-MM-DD.jsonl`。

需要剥离的通信职责：

- control status pipe server worker。
- 接收 JSON line。
- 交给 status sink。

不应先剥离的业务职责：

- 控制状态文件落盘。
- RULE_LOAD_RESULT schema 演进。

### 2.4 `ConfigWatcher`

文件：

- `src/rasp_sentry_native/include/config_watcher.h`
- `src/rasp_sentry_native/src/config_watcher.cpp`

当前职责：

- 监听 `rasp_rules.json`。
- 监听 Lua 规则 / 库目录。
- debounce 文件变化。
- 调用 `RuleServer::InvalidateCache()`。
- 向所有 DLL listener 广播 `0x01` reload 到 `amsi_detect_config`。

需要剥离的通信职责：

- `BroadcastReload()` 中的 `WaitNamedPipeW` / `CreateFileW` / `WriteFile` 循环。
- max listener / timeout / broadcast 结果统计。

不应先剥离的业务职责：

- 文件监听。
- debounce。
- 规则缓存 invalidation 时机。

### 2.5 `AmsiStagingWatcher`

文件：

- `src/rasp_sentry_native/include/amsi_staging_watcher.h`
- `src/rasp_sentry_native/src/amsi_staging_watcher.cpp`

当前职责：

- 监听 staging 目录中的 `rasp_mod_amsi.dll`。
- 广播 `0x02` unload 到 `amsi_detect_config`。
- 等待 drain-ack。
- shadow replace DLL。
- 失败时调度 reboot 替换。

需要剥离的通信职责：

- `BroadcastUnload()` 中的 config pipe 广播。

不应先剥离的业务职责：

- staging 目录监听。
- drain-ack 等待策略。
- DLL 替换 / reboot 调度。

### 2.6 DLL 侧 IPC 仍存在

当前 DLL / rule engine 侧还存在以下 IPC：

| 功能 | 文件 | 说明 |
|---|---|---|
| 拉取规则 | `src/rasp_rule_engine/src/rasp_sentry_base.cpp::ConnectSentry()` | client 连接 `amsi_detect_rules` |
| 上报规则加载状态 | `src/rasp_rule_engine/src/rasp_sentry_base.cpp::SendRuleLoadResult()` | client 写 `amsi_detect_control_status` |
| 发送 detection event | `src/rasp_rule_engine/src/legacy_pipe_event_transport.cpp` | client 写 `amsi_detect_events` |
| 发送 diag log | `src/rasp_rule_engine/src/legacy_diag_pipe_writer.cpp` | client 写 `amsi_detect_events` |
| 监听 reload/unload | `src/rasp_rule_engine/src/rasp_sentry_base.cpp::ConfigPipeThreadProc()` | server 监听 `amsi_detect_config` |
| drain-ack | `src/rasp_mod_amsi/src/amsi_rule_engine.cpp` | unload 时写 `amsi_detect_events` |

本设计只抽 EXE/HostGuard 侧通信模块，不迁移 DLL 侧 IPC。DLL 侧后续应单独做 provider-adapter/transport 抽象。

## 3. 目标模块

建议新增独立模块：

```text
src/amsi_ipc_host/
  include/
    amsi_ipc_host.h
    amsi_ipc_types.h
    amsi_pipe_names.h
    amsi_pipe_security.h
    named_pipe_server_pool.h
    amsi_rule_channel.h
    amsi_event_channel.h
    amsi_control_status_channel.h
    amsi_config_broadcaster.h
  src/
    amsi_ipc_host.cpp
    amsi_pipe_security.cpp
    named_pipe_server_pool.cpp
    amsi_rule_channel.cpp
    amsi_event_channel.cpp
    amsi_control_status_channel.cpp
    amsi_config_broadcaster.cpp
```

如果短期不想新增顶层目录，可以先放在：

```text
src/rasp_sentry_native/include/ipc/
src/rasp_sentry_native/src/ipc/
```

但从 HostGuard 迁移角度，独立目录更清晰。

## 4. 对外接口设计

### 4.1 pipe 名称配置

```cpp
struct AmsiIpcHostConfig {
    std::wstring rulesPipeName = LR"(\\.\pipe\amsi_detect_rules)";
    std::wstring eventsPipeName = LR"(\\.\pipe\amsi_detect_events)";
    std::wstring controlStatusPipeName = LR"(\\.\pipe\amsi_detect_control_status)";
    std::wstring configPipeName = LR"(\\.\pipe\amsi_detect_config)";

    int ruleServerThreads = 8;
    int eventCollectorThreads = 16;
    int controlStatusThreads = 2;

    int configMaxListeners = 32;
    DWORD configBroadcastTimeoutMs = 500;
};
```

说明：

- 默认仍使用当前 `amsi_detect_*` 管道名。
- HostGuard 未来如需改 pipe name，只改 config，不改业务代码。

### 4.2 规则提供接口

```cpp
struct AmsiRuleResponse {
    std::string json;
};

class IAmsiRuleProvider {
public:
    virtual ~IAmsiRuleProvider() = default;

    virtual bool BuildRulesResponse(const std::string& command,
                                    AmsiRuleResponse& out,
                                    std::string& error) = 0;

    virtual void InvalidateRuleCache() = 0;
};
```

当前 `RuleServer` 后续作为 `IAmsiRuleProvider` 实现。

设计约束：

- `AmsiRuleChannel` 只处理 pipe 协议。
- `IAmsiRuleProvider` 才知道 `GET_RULES` / `GET_ALL_RULES` 的业务含义。
- `command` 第一版只允许 `GET_RULES` 和 `GET_ALL_RULES`。
- 未知 `command` 必须返回失败，并通过 `error` 输出可诊断原因；channel 不得自行推断规则内容，也不得写入新的错误 JSON 或错误字符串。
- 规则 JSON、Lua bytecode、version/hash 等由 provider 决定。

### 4.3 事件 sink 接口

```cpp
struct AmsiEventLine {
    std::string jsonLine;
};

class IAmsiEventSink {
public:
    virtual ~IAmsiEventSink() = default;
    virtual void OnEventLine(const AmsiEventLine& event) = 0;
};
```

当前 `EventCollector` 后续拆成：

- `AmsiEventChannel`：pipe 接收。
- `JsonlEventSink`：落盘。
- `DrainAckObserver` 或 `DrainAckQueue`：drain-ack 提取。

边界约束：

- `AmsiEventChannel` 只做按行接收和透传。
- `AmsiEventChannel` 不识别 `cat`、`rule`、`sensor`、`drain-ack` 等业务字段。
- DetectionEvent / DiagLog / drain-ack 的分类由 `IAmsiEventSink` 或其下游实现负责。

### 4.4 控制状态 sink 接口

```cpp
struct AmsiControlStatusLine {
    std::string jsonLine;
};

class IAmsiControlStatusSink {
public:
    virtual ~IAmsiControlStatusSink() = default;
    virtual void OnControlStatusLine(const AmsiControlStatusLine& status) = 0;
};
```

当前 `ControlStatusCollector` 后续拆成：

- `AmsiControlStatusChannel`：pipe 接收。
- `JsonlControlStatusSink`：落盘。

边界约束：

- `AmsiControlStatusChannel` 只做按行接收和透传。
- `AmsiControlStatusChannel` 不解析 RULE_LOAD_RESULT 的成功/失败语义。
- RULE_LOAD_RESULT 的业务解释由 `IAmsiControlStatusSink` 或 HostGuard 上层模块负责。

### 4.5 config 广播接口

```cpp
enum class AmsiControlSignal : uint8_t {
    Reload = 0x01,
    Unload = 0x02,
};

struct AmsiBroadcastResult {
    int reached = 0;
    DWORD lastError = 0;
};

class AmsiConfigBroadcaster {
public:
    explicit AmsiConfigBroadcaster(std::wstring configPipeName);

    AmsiBroadcastResult Broadcast(AmsiControlSignal signal,
                                  int maxListeners,
                                  DWORD timeoutMs);
};
```

设计约束：

- 仍保持当前 1-byte 协议。
- 不在本批改成 JSON control-plane。
- 不新增 ACK 协议。
- `ConfigWatcher` 和 `AmsiStagingWatcher` 共用该 broadcaster。

### 4.6 高层 façade

```cpp
class AmsiIpcHost {
public:
    AmsiIpcHost(AmsiIpcHostConfig config,
                IAmsiRuleProvider& ruleProvider,
                IAmsiEventSink& eventSink,
                IAmsiControlStatusSink& controlStatusSink);

    bool Start();
    void Stop();

    void InvalidateRules();

    AmsiBroadcastResult BroadcastReload();
    AmsiBroadcastResult BroadcastUnload();
};
```

HostGuard 未来只依赖该 façade：

```cpp
HostGuardRuleProvider rules;
HostGuardEventSink events;
HostGuardControlStatusSink status;

AmsiIpcHost ipc(config, rules, events, status);
ipc.Start();

// 规则变化
ipc.InvalidateRules();
ipc.BroadcastReload();

// DLL 替换
ipc.BroadcastUnload();

ipc.Stop();
```

## 5. 分层边界

### 5.1 `NamedPipeServerPool`

职责：

- 根据 pipe name 创建多个 worker。
- 每个 worker 循环 `CreateNamedPipeW` / `ConnectNamedPipe`。
- 将连接后的 `HANDLE` 交给 handler。
- Stop 时通过 dummy client 解除 blocking wait。

禁止：

- 不解析规则 JSON。
- 不识别 DetectionEvent。
- 不识别 RULE_LOAD_RESULT。
- 不写日志文件。
- 不触发 reload/unload。

### 5.2 `AmsiRuleChannel`

职责：

- 读取一条 rule request。
- 调用 `IAmsiRuleProvider`。
- 写回 rule response。

禁止：

- 不读取规则文件。
- 不 inline Lua。
- 不缓存规则。
- 不编译 bytecode。

### 5.3 `AmsiEventChannel`

职责：

- 读取 events pipe payload。
- 交给 `IAmsiEventSink`。

禁止：

- 不写 JSONL 文件。
- 不知道 drain-ack 的业务处理。
- 不改变 DetectionEvent / DiagLog schema。

### 5.4 `AmsiControlStatusChannel`

职责：

- 读取 `RULE_LOAD_RESULT` JSON line。
- 交给 `IAmsiControlStatusSink`。

禁止：

- 不解析规则版本语义。
- 不参与 reload 决策。
- 不写生产日志文件。

### 5.5 `AmsiConfigBroadcaster`

职责：

- 向 `amsi_detect_config` 多 listener 广播 1-byte signal。
- 返回 reached count。

禁止：

- 不知道规则缓存。
- 不知道 staging。
- 不等待 drain-ack。
- 不改控制协议。

## 6. 分批实施路线

### Batch 1：抽 pipe names 与 `AmsiConfigBroadcaster`

目标：

- 先收口 reload/unload 广播。
- 保持热更新行为不变。

新增：

```text
src/amsi_ipc_host/include/amsi_pipe_names.h
src/amsi_ipc_host/include/amsi_config_broadcaster.h
src/amsi_ipc_host/src/amsi_config_broadcaster.cpp
```

修改：

- `src/rasp_sentry_native/src/config_watcher.cpp`
- `src/rasp_sentry_native/src/amsi_staging_watcher.cpp`
- `src/rasp_sentry_native/include/config_watcher.h`
- `src/rasp_sentry_native/include/amsi_staging_watcher.h`

不改：

- `RuleServer`
- `EventCollector`
- `ControlStatusCollector`
- DLL 侧代码
- pipe payload schema

验收：

- 修改 `rasp_rules.json` 后 reload 仍能广播到已加载 PowerShell。
- `Broadcast complete - reached N listener(s)` 语义不变。
- staging unload 仍能广播 `0x02`。
- drain-ack 等待逻辑不变。

### Batch 2：抽 `NamedPipeServerPool` + `AmsiRuleChannel`

目标：

- 让 HostGuard 能复用规则 pipe server。
- `RuleServer` 变成 rule provider，不再直接持有 pipe worker 主逻辑。

新增：

```text
src/amsi_ipc_host/include/named_pipe_server_pool.h
src/amsi_ipc_host/include/amsi_rule_channel.h
src/amsi_ipc_host/src/named_pipe_server_pool.cpp
src/amsi_ipc_host/src/amsi_rule_channel.cpp
```

修改：

- `src/rasp_sentry_native/include/rule_server.h`
- `src/rasp_sentry_native/src/rule_server.cpp`

保留：

- `RuleServer::BuildAssembledJson()`
- `RuleServer::FilterAmsiProviderRules()`
- Lua source / bytecode 处理
- `InvalidateCache()`

验收：

- DLL 初始化仍可通过 `amsi_detect_rules` 拉规则。
- `GET_ALL_RULES` / `GET_RULES` 行为不变。
- bytecode/source 规则响应不变。
- reload 后 cache invalidation 仍生效。

#### Batch 2 详细设计

Batch 2 只拆 `amsi_detect_rules` 通信通道，不改变规则组装、规则缓存、Lua source/bytecode 处理或 DLL 拉取规则协议。

##### 2.1 目标边界

本批目标：

- 将 `RuleServer::ServerLoop()` 中的 pipe worker 主循环迁入通用 `NamedPipeServerPool`。
- 将单连接请求处理迁入 `AmsiRuleChannel`。
- 让 `RuleServer` 实现 `IAmsiRuleProvider`，继续作为规则业务提供方。
- 保持 `RuleServer::kThreadCount == 8`。
- 保持 `amsi_detect_rules` pipe name 不变。

本批非目标：

- 不改 `BuildAssembledJson()`。
- 不改 `FilterAmsiProviderRules()`。
- 不改 `InlineGlobalLibraries()` / `InlineScriptFiles()` / Lua bytecode 编译链路。
- 不改 `m_cachedAssembled` / `m_cachedAmsiRules` cache 语义。
- 不改 DLL 侧 `ConnectSentry()`。
- 不改规则响应 JSON schema。
- 不接 HostGuard SDK。

##### 2.2 命令契约

`AmsiRuleChannel` 第一版只接受以下命令：

| 命令 | 行为 | 当前兼容来源 |
|---|---|---|
| `GET_ALL_RULES` | 返回 assembled JSON | `RuleServer::GetAssembledJson()` |
| `GET_RULES` | 返回 AMSI-filtered JSON | `RuleServer::GetAmsiRulesJson()` |

未知命令：

- 保持当前 wire 行为：仅记录 warning，不写有效 payload。
- `IAmsiRuleProvider::BuildRulesResponse()` 必须返回 `false`。
- `error` 必须包含可诊断原因，例如 `unknown command: <command>`。
- `AmsiRuleChannel` 不得自行推断默认规则响应。
- `AmsiRuleChannel` 不得为未知命令写入错误 JSON 或错误字符串，避免改变 DLL 侧兼容行为。

##### 2.3 接口草案

```cpp
class INamedPipeClientHandler {
public:
    virtual ~INamedPipeClientHandler() = default;
    virtual void HandleClient(HANDLE pipe) = 0;
};

class NamedPipeServerPool {
public:
    NamedPipeServerPool(std::wstring pipeName,
                        int threadCount,
                        INamedPipeClientHandler& handler);

    bool Start();
    void Stop();
};
```

约束：

- `NamedPipeServerPool` 可以 include Windows 头和调用 Win32 pipe API。
- `NamedPipeServerPool` 不知道 `GET_RULES` / `GET_ALL_RULES`。
- `NamedPipeServerPool` 不知道规则 JSON。
- `NamedPipeServerPool::Stop()` 必须保留 dummy client 解除 `ConnectNamedPipe()` 的行为。

```cpp
class AmsiRuleChannel : public INamedPipeClientHandler {
public:
    explicit AmsiRuleChannel(IAmsiRuleProvider& provider);
    void HandleClient(HANDLE pipe) override;
};
```

约束：

- `AmsiRuleChannel` 只负责读取 command、调用 provider、写回 response。
- `AmsiRuleChannel` 不读取规则文件。
- `AmsiRuleChannel` 不缓存规则。
- `AmsiRuleChannel` 不解析 Lua / PCRE2。
- `AmsiRuleChannel` 不依赖 HostGuard SDK。

##### 2.4 RuleServer 改造形态

改造后 `RuleServer` 保留原业务职责：

```cpp
class RuleServer : public IAmsiRuleProvider {
public:
    static constexpr const wchar_t* kPipeName = L"amsi_detect_rules";
    static constexpr int kThreadCount = 8;

    explicit RuleServer(std::string rulesPath);
    ~RuleServer();

    void Start();
    void Stop();
    void InvalidateCache();

    bool BuildRulesResponse(const std::string& command,
                            AmsiRuleResponse& out,
                            std::string& error) override;

private:
    const std::string& GetAssembledJson();
    const std::string& GetAmsiRulesJson();

    std::string BuildAssembledJson();
    std::string FilterAmsiProviderRules(const std::string& assembledJson);

    AmsiRuleChannel ruleChannel_;
    NamedPipeServerPool rulePipePool_;
};
```

实现说明：

- `BuildRulesResponse("GET_ALL_RULES")` 返回 `GetAssembledJson()`。
- `BuildRulesResponse("GET_RULES")` 返回 `GetAmsiRulesJson()`。
- 未知 command 返回 `false`。
- `Start()` 只启动 `rulePipePool_`。
- `Stop()` 只停止 `rulePipePool_`。
- `InvalidateCache()` 继续清空 `m_cachedAssembled` / `m_cachedAmsiRules`。

生命周期约束：

- `ruleChannel_` 必须先于 `rulePipePool_` 构造完成。
- `rulePipePool_` 只能持有已存在的 handler 引用，不拥有 provider。
- `Stop()` 必须先停止 `rulePipePool_`，再允许 `RuleServer` 析构 provider/cache 相关成员。
- 不允许 `NamedPipeServerPool` 后台线程在 `RuleServer` 析构后继续访问 `ruleChannel_` 或 `RuleServer`。

##### 2.5 测试计划

新增测试目标：

```text
amsi_rule_channel_tests
named_pipe_server_pool_tests
```

`amsi_rule_channel_tests` 覆盖：

- fake provider 收到 `GET_RULES`。
- fake provider 收到 `GET_ALL_RULES`。
- fake provider 返回 JSON 后 channel 写回原始响应。
- 未知命令不崩溃，并走 provider failure 路径。
- 空请求不崩溃。

`named_pipe_server_pool_tests` 覆盖：

- `Start()` 后可接受一个本地 test client。
- `Stop()` 能解除阻塞等待。
- 无 client 时 `Stop()` 不挂死。
- 多线程 worker 数按配置创建。

如果真实 pipe 单测在 CI 中不稳定，可先将 `NamedPipeServerPool` 的 pipe 创建抽成 test seam；但不要把 seam 暴露给生产调用方。

##### 2.6 回归验证

必须验证：

- `rasp_sentry.exe` Release build 通过。
- DLL 初始化能通过 `amsi_detect_rules` 获取规则。
- `GET_ALL_RULES` 响应与改造前字节级一致，包括尾部换行策略。
- `GET_RULES` 响应与改造前字节级一致，包括尾部换行策略。
- 如果测试框架难以稳定做字节级比较，至少必须做 canonical JSON 语义一致，并额外断言是否追加单个 `\n` 的 wire 行为不变。
- 修改 `rasp_rules.json` 后 reload 仍触发 cache invalidation。
- source 规则、bytecode 规则、缺省 `scriptEncoding` 规则混跑不变。

##### 2.7 风险

| 风险 | 说明 | 缓解 |
|---|---|---|
| cache 锁语义漂移 | `RuleServer` cache 与 pipe worker 解耦后可能误改 `m_cacheLock` | `BuildRulesResponse()` 内继续复用原 `Get*Json()` |
| Stop 挂死 | 原实现依赖 dummy client 解除 `ConnectNamedPipe()` | `NamedPipeServerPool::Stop()` 必须保留 dummy client |
| 未知命令 wire 行为变化 | 当前实现对未知命令有兼容日志/响应行为 | 实现前先固化旧行为测试 |
| bytecode 响应变化 | RuleServer 同时承载 Lua 编译 | 本批不改任何规则组装函数 |

##### 2.8 静态门禁

Batch 2 完成后建议检查：

- `RuleServer` 不再直接调用 `CreateNamedPipeW`。
- `RuleServer` 不再直接调用 `ConnectNamedPipe`。
- `RuleServer` 不再直接管理 `HANDLE m_threads[kThreadCount]`。
- `AmsiRuleChannel` 不 include Lua / PCRE2 / HostGuard SDK。
- `NamedPipeServerPool` 不 include `rule_server.h`。
- `NamedPipeServerPool` 不出现 `GET_RULES` / `GET_ALL_RULES` 字符串。

### Batch 3：抽 `AmsiEventChannel`

目标：

- 让 HostGuard 能复用 events pipe server。
- `EventCollector` 变成事件 sink / drain-ack owner。

新增：

```text
src/amsi_ipc_host/include/amsi_event_channel.h
src/amsi_ipc_host/include/amsi_event_sink.h
src/amsi_ipc_host/src/amsi_event_channel.cpp
```

修改：

- `src/rasp_sentry_native/include/event_collector.h`
- `src/rasp_sentry_native/src/event_collector.cpp`

保留：

- JSONL 落盘。
- drain-ack 识别。
- `DrainAckQueue`。

验收：

- DetectionEvent 仍写入 `rasp-events-*.jsonl`。
- DiagLog 仍写入。
- drain-ack 仍能唤醒 `AmsiStagingWatcher`。

### Batch 4：抽 `AmsiControlStatusChannel`

目标：

- 让 HostGuard 能复用 control status pipe server。

新增：

```text
src/amsi_ipc_host/include/amsi_control_status_channel.h
src/amsi_ipc_host/include/amsi_control_status_sink.h
src/amsi_ipc_host/src/amsi_control_status_channel.cpp
```

修改：

- `src/rasp_sentry_native/include/control_status_collector.h`
- `src/rasp_sentry_native/src/control_status_collector.cpp`

验收：

- RULE_LOAD_RESULT 仍写入 `rasp-control-status-*.jsonl`。
- 成功/失败/last-good 语义不变。

### Batch 5：新增 `AmsiIpcHost` façade

目标：

- `rasp_sentry_native/src/main.cpp` 不再直接管理多个 IPC 组件。
- HostGuard 未来可直接复用 façade。

新增：

```text
src/amsi_ipc_host/include/amsi_ipc_host.h
src/amsi_ipc_host/src/amsi_ipc_host.cpp
```

修改：

- `src/rasp_sentry_native/src/main.cpp`

验收：

- `rasp_sentry.exe` 启停行为不变。
- 线程数量与当前配置一致。
- rules/events/control_status/config 四条通道均可用。

## 7. 暂不建议修改的内容

当前阶段不要做：

- 不改 DLL 侧 `ConnectSentry()`。
- 不改 DLL 侧 `ConfigPipeThreadProc()`。
- 不改 events / rules / control status payload schema。
- 不把 config pipe 从 1-byte 改成 JSON。
- 不接 HostGuard SDK。
- 不做规则加密。
- 不改变 RuleServer 的 Lua bytecode/source 处理。
- 不改变 EventCollector 的 JSONL 落盘。
- 不改变 AmsiStagingWatcher 的 DLL 替换策略。

原因：

- 当前目标是 IPC 能力可迁移，不是重写控制面。
- HostGuard 内部规则中心 / 事件总线语义尚未冻结。
- 一次性改协议和通信层会扩大验证面。

## 8. 风险与门禁

### 8.1 风险

| 风险 | 说明 | 缓解 |
|---|---|---|
| 热更新回归 | `ConfigWatcher` 广播逻辑已修过，抽离时容易回退 | Batch 1 单独做，保留 reached count 测试 |
| 规则响应变化 | `RuleServer` 同时处理 pipe 和规则组装 | Batch 2 只抽 channel，不改 provider 逻辑 |
| drain-ack 丢失 | `EventCollector` 与 `AmsiStagingWatcher` 有共享队列 | Batch 3 保留 `DrainAckQueue` owner |
| 状态通道丢失 | `ControlStatusCollector` 是较新能力 | Batch 4 单独抽，不混入 events |
| HostGuard 耦合过早 | 直接 include HostGuard SDK 会污染模块 | 本阶段禁止 HostGuard SDK |

### 8.2 静态门禁建议

新增脚本或扩展现有检查：

- `amsi_ipc_host` 允许使用 Win32 pipe API。
- `RuleServer` 后续不应直接出现 `CreateNamedPipeW`。
- `EventCollector` 后续不应直接出现 `CreateNamedPipeW`。
- `ControlStatusCollector` 后续不应直接出现 `CreateNamedPipeW`。
- `ConfigWatcher` / `AmsiStagingWatcher` 后续不应直接出现 config pipe `CreateFileW` / `WriteFile` 广播循环。
- `amsi_ipc_host` 不 include HostGuard SDK。
- `amsi_ipc_host` 不 include Lua / PCRE2 / AMSI COM 头。

## 9. 推荐下一步

建议下一步只做 Batch 1：

```text
抽 AmsiConfigBroadcaster + pipe names 常量
```

理由：

- 改动面最小。
- 直接服务 HostGuard 后续 reload/unload。
- 能保护最近修复过的 hot reload 行为。
- 不碰规则响应和事件收集主链路。

Batch 1 通过后，再进入 Batch 2 抽 `RuleChannel`。
