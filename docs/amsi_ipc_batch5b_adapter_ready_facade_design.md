# Batch 5b Adapter-ready Facade 设计

## 1. 当前阶段

Batch 5a 已经新增 `AmsiIpcHost`，把 `rasp_sentry_native/main.cpp` 中分散的启动/停止逻辑收口到 facade。

当前 `AmsiIpcHost` 仍是 demo facade：

- 直接创建 `RuleServer`
- 直接创建 `EventCollector`
- 直接创建 `ControlStatusCollector`
- 直接创建 `ConfigWatcher`
- 直接创建 `AmsiStagingWatcher`
- 仍依赖 `logDir` / `rulesPath` / `stagingDir` 路径型配置

Batch 5b 的目标是把 facade 的迁移边界设计成 adapter-ready，但本批只更新设计文档，不修改生产代码。

## 2. 核心结论

当前不建议立刻用 `ruleProvider` 注入彻底替换 `rulesPath`。

更合理的落地顺序是：

1. 短期保留 `rulesPath`，仅作为 demo fallback。
2. 在 Batch 5b 文档中正式声明：HostGuard 不应依赖 `rulesPath`。
3. Batch 5c 先落地 `IAmsiEventSink` / `IAmsiControlStatusSink` 注入。
4. Batch 5d 再拆 `RuleServer`，把规则读取、规则组装、规则 cache、Lua bytecode 编译和 rules pipe 生命周期分离。
5. 到 Batch 5d 之后，再把 `IAmsiRuleProvider` 注入变成 HostGuard 主路径。

原因是当前 `RuleServer` 不是纯 provider。它同时承担：

- 规则文件读取
- JSON 组装
- `globalLibraries` inline
- Lua script inline
- Lua bytecode 编译
- cache
- `IAmsiRuleProvider`
- `AmsiRuleChannel`
- `NamedPipeServerPool`

如果现在直接把 `rulesPath` 替换成规则字符串或外部 provider，会把这些职责硬拆在同一批里，风险偏高，也容易破坏当前 demo 闭环。

## 3. 目标

Batch 5b 目标：

- 定义 demo mode / injected mode 的迁移边界。
- 明确 `rulesPath` 只是 demo fallback。
- 明确 HostGuard 不应依赖 `rulesPath`、`ConfigWatcher`、`AmsiStagingWatcher`。
- 明确 Batch 5c 只做 Event / ControlStatus sink 注入。
- 明确 Batch 5d 才拆 `RuleServer` / `IAmsiRuleProvider`。
- 给出后续 HostGuard 接入时的推荐形态。

## 4. 非目标

Batch 5b 不做：

- 不改生产代码。
- 不接 HostGuard / EDR SDK。
- 不删除 `rasp_sentry.exe`。
- 不改 pipe name。
- 不改 JSON schema。
- 不改 DLL 侧 IPC client。
- 不改 reload / unload wire 语义。
- 不拆 `RuleServer` 实现。
- 不把 `rulesPath` 从当前 demo config 中删除。
- 不改 `EventCollector` / `ControlStatusCollector` JSONL 落盘行为。

## 5. `AmsiIpcHostConfig` 语义

当前 demo config：

```cpp
struct AmsiIpcHostConfig {
    std::string logDir;
    std::string rulesPath;
    std::string stagingDir;
};
```

Batch 5b 对三个字段的定位：

| 字段 | 当前用途 | HostGuard 化后的定位 |
|---|---|---|
| `logDir` | demo JSONL 日志目录 | demo fallback；HostGuard 应注入 event/status sink |
| `rulesPath` | demo 规则文件路径 | demo fallback；HostGuard 不应依赖 |
| `stagingDir` | demo DLL staging 目录 | demo fallback；HostGuard 应由自身升级模块接管 |

硬边界：

- `rulesPath` 只服务当前 demo `RuleServer`。
- HostGuard 模式下不应通过 `rulesPath` 传递规则。
- HostGuard 模式下规则来源应由外部规则中心、配置中心或内存 provider 管理。
- `AmsiIpcHost` 不应长期承担读取规则文件、监听规则文件变化、解析规则文件的职责。

## 6. 未来 `AmsiIpcHostAdapters` 草案

建议后续引入：

```cpp
struct AmsiIpcHostAdapters {
    amsi_ipc::IAmsiRuleProvider* ruleProvider = nullptr;
    amsi_ipc::IAmsiEventSink* eventSink = nullptr;
    amsi_ipc::IAmsiControlStatusSink* controlStatusSink = nullptr;
};
```

语义：

- `nullptr` 表示使用 demo 默认实现。
- 非空表示由外部 HostGuard adapter 提供实现。
- adapter 生命周期由调用方保证，必须覆盖 `AmsiIpcHost::Start()` 到 `AmsiIpcHost::Stop()`。
- `AmsiIpcHost` 不拥有外部注入 adapter。
- `AmsiIpcHost` 只负责 IPC 生命周期组装，不负责 adapter 的业务语义。

推荐构造函数形态：

```cpp
class AmsiIpcHost {
public:
    explicit AmsiIpcHost(AmsiIpcHostConfig config);

    AmsiIpcHost(AmsiIpcHostConfig config,
                AmsiIpcHostAdapters adapters);

    bool Start();
    void Stop();
};
```

默认构造仍保持当前 demo 行为。

## 7. Demo Mode

当所有 adapter 均为 `nullptr` 时：

- `AmsiIpcHost` 创建 `RuleServer(config.rulesPath)`。
- `AmsiIpcHost` 创建 `EventCollector(config.logDir)`。
- `AmsiIpcHost` 创建 `ControlStatusCollector(config.logDir)`。
- `AmsiIpcHost` 创建 `ConfigWatcher(config.rulesPath, ruleServer)`。
- `AmsiIpcHost` 创建 `AmsiStagingWatcher(config.stagingDir, drainAckQueue)`。

该模式用于：

- 当前 `rasp_sentry.exe`。
- 测试机独立 demo。
- HostGuard 接入前的兼容运行。

要求：

- 行为必须与 Batch 5a 保持一致。
- 不改变四条 pipe 行为。
- 不改变 JSONL 落盘。
- 不改变 reload / unload 广播。
- `rulesPath` 只在这个模式下有业务意义。

## 8. Injected Mode

HostGuard 模式下，建议逐步注入：

- `HostGuardEventSink : IAmsiEventSink`
- `HostGuardControlStatusSink : IAmsiControlStatusSink`
- `HostGuardRuleProvider : IAmsiRuleProvider`

示例：

```cpp
HostGuardEventSink eventSink;
HostGuardControlStatusSink statusSink;

AmsiIpcHostConfig config;
config.logDir = "";
config.rulesPath = "";   // HostGuard 不依赖 rulesPath
config.stagingDir = "";

AmsiIpcHostAdapters adapters;
adapters.eventSink = &eventSink;
adapters.controlStatusSink = &statusSink;

AmsiIpcHost host(config, adapters);
host.Start();
```

Batch 5c 只建议支持 `eventSink` 和 `controlStatusSink` 注入。

`ruleProvider` 注入建议等 Batch 5d 拆分 `RuleServer` 后再进入主路径。

## 9. Batch 5c：Event / ControlStatus sink 注入

Batch 5c 允许：

- `AmsiIpcHostAdapters` 增加 `eventSink`。
- `AmsiIpcHostAdapters` 增加 `controlStatusSink`。
- 未注入时继续创建 demo `EventCollector` / `ControlStatusCollector`。
- 注入时使用外部 sink 承接 payload。
- 保持 `AmsiEventChannel` / `AmsiControlStatusChannel` 的 transport-only 边界。
- 保持 demo mode 默认行为不变。

Batch 5c 禁止：

- 不拆 `RuleServer`。
- 不改 `rulesPath` 语义。
- 不改 rules pipe。
- 不改 DLL 侧发送逻辑。
- 不接 HostGuard SDK。
- 不让 channel 识别业务 JSON schema。

验收：

- demo mode 行为不变。
- 注入 fake event sink 后，`amsi_detect_events` payload 进入 fake sink。
- 注入 fake control status sink 后，`RULE_LOAD_RESULT` payload 进入 fake sink。
- 未注入时仍写 JSONL。
- IPC channel tests 通过。
- `rasp_sentry.exe` Release build 通过。

## 10. Batch 5d：RuleServer 拆分

Batch 5d 才处理规则 provider 主路径。

目标拆分：

```text
RuleServer 当前职责
  -> DemoFileRuleProvider
     - rulesPath
     - 规则文件读取
     - globalLibraries inline
     - Lua script inline
     - Lua bytecode 编译
     - cache

  -> AmsiRuleChannel
     - pipe command 读取
     - 调 IAmsiRuleProvider
     - response 写回

  -> NamedPipeServerPool
     - pipe worker 生命周期
```

Batch 5d 允许：

- 抽出 `DemoFileRuleProvider : IAmsiRuleProvider`。
- 让 `AmsiIpcHost` 统一持有 `AmsiRuleChannel` / `NamedPipeServerPool`。
- 让 `RuleServer` 退化为 demo provider，或被 `DemoFileRuleProvider` 替换。
- 为 HostGuard `IAmsiRuleProvider` 注入铺路。

Batch 5d 禁止：

- 不改 `GET_RULES` / `GET_ALL_RULES` wire 语义。
- 不改 assembled JSON / AMSI-filtered JSON 生成语义。
- 不改 DLL `ConnectSentry()`。
- 不改 reload / unload pipe 协议。

## 11. HostGuard RuleProvider 目标形态

HostGuard 不应通过 `rulesPath` 传递规则。

推荐形态：

```cpp
class HostGuardAmsiRuleProvider : public amsi_ipc::IAmsiRuleProvider {
public:
    bool UpdateRules(std::string assembledRulesJson);

    bool BuildRulesResponse(const std::string& command,
                            amsi_ipc::AmsiRuleResponse& out,
                            std::string& error) override
    {
        if (_stricmp(command.c_str(), "GET_ALL_RULES") == 0) {
            out.json = CurrentAssembledRulesJson();
            return !out.json.empty();
        }
        if (_stricmp(command.c_str(), "GET_RULES") == 0) {
            out.json = CurrentAmsiRulesJson();
            return !out.json.empty();
        }
        error = "unknown command";
        return false;
    }

    void InvalidateRuleCache() override
    {
        MarkRuleCacheDirty();
    }
};
```

HostGuard 负责：

- 云端规则 / 本地策略 / 数据库规则获取。
- 规则版本和 hash 管理。
- 规则合法性校验。
- 规则 cache 管理。
- 是否预编译 Lua bytecode。
- 规则更新后触发 reload broadcast。

`AmsiIpcHost` 负责：

- 维护 `amsi_detect_rules` 通道。
- 收到 DLL `GET_ALL_RULES` / `GET_RULES` 后调用 provider。
- 把 provider 返回的 JSON 写回 DLL。
- 不读取规则文件。
- 不解析规则业务语义。
- 不管理 HostGuard 规则生命周期。

## 12. Watcher 边界

`ConfigWatcher` 和 `AmsiStagingWatcher` 是 demo-only dependency。

HostGuard 化时：

- `ConfigWatcher` 应由 HostGuard 配置中心 / 规则中心替代。
- `AmsiStagingWatcher` 应由 HostGuard 升级 / 文件替换模块替代。
- `AmsiIpcHost` 不应把 watcher 固定为不可替换成员。
- HostGuard 可以直接调用 future `BroadcastReload()` / `BroadcastUnload()` facade API。

## 13. 分批路线

### Batch 5b：Adapter-ready design-only

允许：

- 更新文档。
- 冻结 `rulesPath` demo fallback 语义。
- 冻结 5c / 5d / 5e 路线。

禁止：

- 不改代码。
- 不改生产行为。

### Batch 5c：Event / ControlStatus sink 注入

允许：

- 新增 `AmsiIpcHostAdapters::eventSink`。
- 新增 `AmsiIpcHostAdapters::controlStatusSink`。
- `AmsiIpcHost` 未注入时创建 demo collector。
- 注入时使用外部 sink。

禁止：

- 不拆 `RuleServer`。
- 不改 rules pipe。
- 不改 `rulesPath`。
- 不接 HostGuard SDK。

### Batch 5d：RuleServer 拆分

允许：

- 抽 `DemoFileRuleProvider`。
- 让 `AmsiIpcHost` 统一持有 rules pipe channel / pool。
- 准备 `IAmsiRuleProvider` 注入主路径。

禁止：

- 不改 wire 语义。
- 不改 DLL `ConnectSentry()`。
- 不改规则 JSON schema。

### Batch 5e：HostGuard injected mode

允许：

- HostGuard 注入 `IAmsiRuleProvider`。
- HostGuard 注入 `IAmsiEventSink`。
- HostGuard 注入 `IAmsiControlStatusSink`。
- HostGuard 禁用 demo watcher。

禁止：

- 不让 HostGuard 直接操作 `NamedPipeServerPool`。
- 不让 HostGuard 依赖 `rulesPath`。
- 不让 channel 层加入业务语义。

## 14. 风险

| 风险 | 说明 | 缓解 |
|---|---|---|
| 过早替换 `rulesPath` | 会迫使同批拆 RuleServer 多个职责 | 5b 只文档，5c 先注入 event/status，5d 再拆规则 |
| facade 继续 hard-code demo 类 | HostGuard 迁移仍被 demo 绑定 | 引入 adapters，逐步注入 |
| RuleServer 拆分过早 | 规则链路复杂，回归风险高 | 第二阶段处理，先保持 demo 闭环 |
| sink 生命周期悬挂 | 外部 adapter 被提前释放 | adapter 生命周期必须覆盖 Start/Stop |
| channel 进入业务层 | transport 与 schema 耦合 | channel 只传 payload，业务在 provider/sink |

## 15. 当前最终结论

当前方式可以接受，方向正确。

但落地顺序必须收敛为：

```text
Batch 5b：文档声明 rulesPath 仅为 demo fallback
Batch 5c：先做 Event / ControlStatus sink 注入
Batch 5d：拆 RuleServer 为纯 provider + channel/pool
Batch 5e：HostGuard 注入 ruleProvider 成为主路径
```

在 Batch 5d 之前，不应删除 `rulesPath`，也不应把 `ruleProvider` 注入作为生产主路径。

## 16. Batch 5c 实现说明

Batch 5c 已按本设计中的低风险路线实现 Event / ControlStatus sink 注入。

已实现：

- `AmsiIpcHostAdapters::eventSink`
- `AmsiIpcHostAdapters::controlStatusSink`
- `AmsiIpcHost(config, adapters)` 构造函数
- 未注入 `eventSink` 时继续创建 demo `EventCollector`
- 未注入 `controlStatusSink` 时继续创建 demo `ControlStatusCollector`
- 注入 `eventSink` 时，由 `AmsiIpcHost` 直接组装 `AmsiEventChannel + NamedPipeServerPool`
- 注入 `controlStatusSink` 时，由 `AmsiIpcHost` 直接组装 `AmsiControlStatusChannel + NamedPipeServerPool`

保持不变：

- 未拆 `RuleServer`
- 未改 `rulesPath`
- 未改 rules pipe
- 未改 `GET_ALL_RULES` / `GET_RULES`
- 未改 DLL `ConnectSentry()`
- 未改 events/control-status wire payload
- 未接 HostGuard SDK

重要边界：

- 注入 `eventSink` 时，当前 demo `AmsiStagingWatcher` 会被禁用。
- 原因是 demo `AmsiStagingWatcher` 依赖 `EventCollector::DrainAckQueue`，而 injected event sink 模式下不再创建 demo `EventCollector`。
- HostGuard 模式下，DLL staging、unload、drain-ack 等 lifecycle 行为应由 HostGuard 自身模块处理，而不是依赖 demo watcher。

Batch 5c 验收重点：

- fake event sink 能通过 `\\.\pipe\amsi_detect_events` 收到 payload。
- fake control status sink 能通过 `\\.\pipe\amsi_detect_control_status` 收到 payload。
- 未注入时 demo collector 行为保持不变。
- `rasp_sentry.exe` Release build 通过。
- 不修改规则链路和 DLL 侧 IPC。
