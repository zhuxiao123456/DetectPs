﻿# Batch 5d RuleProvider 拆分设计

## 1. 当前阶段

Batch 5c 已经完成 `AmsiIpcHost` 的 Event / ControlStatus sink 注入：

- `AmsiIpcHostAdapters::eventSink`
- `AmsiIpcHostAdapters::controlStatusSink`
- 未注入时继续走 demo `EventCollector` / `ControlStatusCollector`
- 注入时由 `AmsiIpcHost` 直接组装 channel + pool

当前剩余最大耦合点是 rules 通道。

`RuleServer` 当前并不是纯规则 provider，而是混合了：

- 规则文件路径 `rulesPath`
- 规则文件读取
- JSON 组装
- `globalLibraries` inline
- Lua script inline
- Lua bytecode 编译
- 规则 cache
- `IAmsiRuleProvider`
- `AmsiRuleChannel`
- `NamedPipeServerPool`

Batch 5d 的目标是拆开这些职责，让 `AmsiIpcHost` 能在后续 HostGuard 模式下注入外部 `IAmsiRuleProvider`，同时保留当前 demo 行为。

## 2. 一句话结论

Batch 5d 不直接删除 `rulesPath`，也不改变 DLL 拉规则协议。

本批目标是：

```text
RuleServer 当前混合体
  -> DemoFileRuleProvider：负责 demo 规则文件读取/组装/cache/bytecode
  -> AmsiIpcHost：负责 rules pipe channel/pool 生命周期
```

这样 HostGuard 后续只需要实现 `IAmsiRuleProvider`，再注入给 `AmsiIpcHost`，不需要依赖 demo `rulesPath` 或 `RuleServer`。

## 3. 非目标

Batch 5d 不做：

- 不改 DLL `RaspSentryBase::ConnectSentry()`。
- 不改 `GET_ALL_RULES` / `GET_RULES` wire 语义。
- 不改 `amsi_detect_rules` pipe 名称。
- 不改规则 JSON schema。
- 不改 assembled JSON 生成语义。
- 不改 AMSI-filtered JSON 生成语义。
- 不改 Lua bytecode 编译结果。
- 不接 HostGuard SDK。
- 不删除 demo `rulesPath`。
- 不删除 `ConfigWatcher`。
- 不删除 `AmsiStagingWatcher`。
- 不改 Event / ControlStatus 注入路径。

## 4. 当前真实规则通道

### 4.1 EXE 侧

文件：

- `src/rasp_sentry_native/include/rule_server.h`
- `src/rasp_sentry_native/src/rule_server.cpp`
- `src/amsi_ipc_host/include/amsi_rule_channel.h`
- `src/amsi_ipc_host/src/amsi_rule_channel.cpp`
- `src/amsi_ipc_host/src/named_pipe_server_pool.cpp`

当前调用链：

```text
AmsiIpcHost::Start()
  -> RuleServer::Start()
    -> NamedPipeServerPool::Start()
      -> ServerLoop()
        -> AmsiRuleChannel::HandleClient()
          -> RuleServer::BuildRulesResponse(command)
```

当前 `RuleServer::BuildRulesResponse()` 语义：

```text
GET_ALL_RULES -> RuleServer::GetAssembledJson()
GET_RULES     -> RuleServer::GetAmsiRulesJson()
unknown       -> false，不写有效 payload
```

### 4.2 DLL 侧

文件：

- `src/rasp_rule_engine/src/rasp_sentry_base.cpp`

当前 DLL 逻辑：

```text
RaspSentryBase::ConnectSentry()
  -> WaitNamedPipeW("\\.\pipe\amsi_detect_rules", 100)
  -> CreateFileW("\\.\pipe\amsi_detect_rules")
  -> WriteFile("GET_ALL_RULES\n")
  -> ReadFile(response)
```

Batch 5d 不修改 DLL 侧。

## 5. 目标职责拆分

### 5.1 `DemoFileRuleProvider`

建议新增：

```cpp
class DemoFileRuleProvider : public amsi_ipc::IAmsiRuleProvider {
public:
    explicit DemoFileRuleProvider(std::string rulesPath);

    bool BuildRulesResponse(const std::string& command,
                            amsi_ipc::AmsiRuleResponse& out,
                            std::string& error) override;

    void InvalidateRuleCache() override;

private:
    const std::string& GetAssembledJson();
    const std::string& GetAmsiRulesJson();

    std::string BuildAssembledJson();
    std::string FilterAmsiProviderRules(const std::string& assembledJson);

    std::string rulesPath_;
    CRITICAL_SECTION cacheLock_;
    std::string cachedAssembled_;
    std::string cachedAmsiRules_;
};
```

职责：

- 读取 demo `rasp_rules.json`。
- 执行当前 `InlineGlobalLibraries()`。
- 执行当前 `InlineScriptFiles()`.
- 执行当前 `CompileAllRulesToBytecode()`.
- 维护当前 assembled / AMSI-filtered cache。
- 实现 `GET_ALL_RULES` / `GET_RULES` 响应。

禁止：

- 不创建 named pipe。
- 不持有 `AmsiRuleChannel`。
- 不持有 `NamedPipeServerPool`。
- 不依赖 `AmsiIpcHost`。
- 不接 HostGuard SDK。

### 5.2 `RuleServer`

Batch 5d 后建议有两种处理方式，优先选择方案 A。

方案 A：删除 `RuleServer` 的 transport 职责，保留为兼容 wrapper。

```text
RuleServer
  -> 内部持有 DemoFileRuleProvider
  -> 转发 BuildRulesResponse()
  -> 仅用于兼容旧调用点，后续可删除
```

方案 B：直接用 `DemoFileRuleProvider` 替代 `RuleServer`。

建议第一批采用方案 A，降低一次性改动风险。

#### 5.2.1 兼容 wrapper 保留范围

Batch 5d-1 完成后，`RuleServer` 作为兼容 wrapper 时只能保留以下 API：

- `RuleServer::RuleServer(std::string rulesPath)`
- `RuleServer::~RuleServer()`
- `RuleServer::BuildRulesResponse(...)`
- `RuleServer::InvalidateCache()`
- `RuleServer::InvalidateRuleCache()`

这些 API 只允许转发到内部 `DemoFileRuleProvider`。

Batch 5d-1 完成后，`RuleServer` 不应继续保留或新增：

- `AmsiRuleChannel` 成员
- `NamedPipeServerPool` 成员
- `Start()`
- `Stop()`
- pipe worker 生命周期
- `CreateNamedPipeW` / `ConnectNamedPipe` 相关逻辑

旧调用点处理：

- `ConfigWatcher` 在 5d-1 阶段可继续接收 `RuleServer*`，但只调用 `InvalidateCache()`。
- `AmsiIpcHost` 在 5d-1 阶段可继续通过 `RuleServer` wrapper 获得 provider 行为。
- 到 5d-2 后，`AmsiIpcHost` 应直接持有 `AmsiRuleChannel` / `NamedPipeServerPool`，不再调用 `RuleServer::Start()` / `Stop()`。

退出条件：

- 当 `AmsiIpcHost` 已支持直接使用 `DemoFileRuleProvider` 和 external `IAmsiRuleProvider` 后，`RuleServer` wrapper 可在单独清理批次删除。
- 删除 wrapper 前必须确认 `ConfigWatcher` 已 provider 化，且没有生产调用点依赖 `RuleServer` 类型。

### 5.3 `AmsiIpcHost`

Batch 5d 后 `AmsiIpcHost` 应统一持有 rules transport：

```cpp
std::unique_ptr<amsi_ipc::AmsiRuleChannel> ruleChannel_;
std::unique_ptr<amsi_ipc::NamedPipeServerPool> rulePipePool_;
std::unique_ptr<DemoFileRuleProvider> demoRuleProvider_;
```

未注入 external rule provider 时：

```text
demoRuleProvider_ = new DemoFileRuleProvider(config.rulesPath)
ruleProvider = demoRuleProvider_.get()
```

注入 external rule provider 时：

```text
ruleProvider = adapters.ruleProvider
不创建 demoRuleProvider_
不使用 rulesPath
```

然后统一：

```text
ruleChannel_ = new AmsiRuleChannel(*ruleProvider)
rulePipePool_ = new NamedPipeServerPool(amsi_detect_rules, 8, *ruleChannel_)
rulePipePool_->Start()
```

## 6. `AmsiIpcHostAdapters` 扩展

Batch 5d 建议扩展：

```cpp
struct AmsiIpcHostAdapters {
    amsi_ipc::IAmsiRuleProvider* ruleProvider = nullptr;
    amsi_ipc::IAmsiEventSink* eventSink = nullptr;
    amsi_ipc::IAmsiControlStatusSink* controlStatusSink = nullptr;
};
```

语义：

- `ruleProvider == nullptr`：demo fallback，使用 `DemoFileRuleProvider(config.rulesPath)`。
- `ruleProvider != nullptr`：HostGuard / 外部 provider 注入，`rulesPath` 不参与规则响应。
- 外部 provider 生命周期由调用方保证，必须覆盖 `AmsiIpcHost::Start()` 到 `Stop()`。
- `AmsiIpcHost` 不拥有外部 provider。

## 7. ConfigWatcher 迁移处理

当前 `ConfigWatcher` 构造依赖 `RuleServer*`，用于：

```text
文件变化
  -> RuleServer::InvalidateCache()
  -> BroadcastReload()
```

Batch 5d 需要调整为依赖 `IAmsiRuleProvider*`：

```cpp
ConfigWatcher(std::string rulesPath,
              amsi_ipc::IAmsiRuleProvider* ruleProvider);
```

文件变化时：

```text
if (ruleProvider) ruleProvider->InvalidateRuleCache();
BroadcastReload();
```

语义保持：

- demo mode 下仍监听 `rasp_rules.json` / `rules/*.lua`。
- injected ruleProvider mode 下默认不应启动 demo `ConfigWatcher`，除非显式选择 demo watcher。

建议 Batch 5d 第一版：

- `ruleProvider` 注入时禁用 demo `ConfigWatcher`。
- `ruleProvider == nullptr` 时继续创建 `ConfigWatcher(config.rulesPath, demoRuleProvider_.get())`。

原因：

- HostGuard 规则更新应由 HostGuard 自己触发 reload。
- demo file watcher 不应绑定到 HostGuard provider。

## 8. 启动顺序

Batch 5d 后建议默认顺序调整为 rules pipe 优先：

```text
AmsiIpcHost::Start()
  1. 准备 rule provider
     - injected provider
     - or demo DemoFileRuleProvider
  2. 创建 AmsiRuleChannel + rules NamedPipeServerPool
  3. 启动 rules pipe pool
  4. 准备 event sink / event pipe pool
  5. 准备 control status sink / control status pipe pool
  6. demo mode 下启动 ConfigWatcher
  7. demo mode 下按条件启动 AmsiStagingWatcher
```

取舍说明：

- 规则拉取是 DLL 初始化的关键路径，`amsi_detect_rules` 应优先可用。
- events / control-status 可以稍后启动；如果 DLL 极早启动并加载规则成功，`RULE_LOAD_RESULT` 可能短暂因为 status pipe 未就绪而无法上报，但这不影响 DLL 获取规则。
- 若团队认为状态上报必须早于规则拉取，可在评审中要求保持 5c 的 event/status first 顺序；但实现前必须固定一种顺序，不允许开发时自行调整。

本设计默认选择 rules first，因为 HostGuard 化后的首要目标是保证 DLL 能尽快获得规则。

停止顺序：

```text
Stop()
  -> 停 AmsiStagingWatcher
  -> 停 ConfigWatcher
  -> 停 rules pipe pool
  -> 停 control status pipe pool / collector
  -> 停 event pipe pool / collector
  -> 释放 provider/channel/pool
```

关键约束：

- `NamedPipeServerPool` 必须先停，再销毁其引用的 channel/provider。
- 外部注入 provider/sink 不由 `AmsiIpcHost` 释放。
- demo provider 必须晚于 rules pipe pool 销毁。

### 8.1 继承 Batch 5c 的 staging watcher 约束

Batch 5d 必须继承 Batch 5c 的边界：

- 如果 `eventSink` 由外部注入，demo `EventCollector` 不会被创建。
- demo `AmsiStagingWatcher` 依赖 `EventCollector::DrainAckQueue`。
- 因此外部 `eventSink` 模式下，demo `AmsiStagingWatcher` 不能默认启动。

HostGuard 模式下：

- DLL staging
- unload broadcast
- drain-ack 等待
- DLL 替换 / 延迟替换

这些 lifecycle 行为应由 HostGuard 自身模块负责，而不是继续依赖 demo watcher。

Batch 5d 不得因为拆 rules pipe 而重新引入对 demo `DrainAckQueue` 的隐式依赖。

## 9. wire 语义冻结

Batch 5d 必须保持：

```text
GET_ALL_RULES -> assembled full JSON
GET_RULES     -> AMSI-filtered JSON
unknown       -> false，不写有效 payload
```

不得修改：

- DLL 仍发送 `GET_ALL_RULES\n`。
- response 仍是 `json + "\n"`。
- unknown command 不返回错误 JSON。
- `AmsiRuleChannel` 不解析规则 JSON。

## 10. 测试方案

### 10.1 provider 单测

新增 `demo_file_rule_provider_tests.cpp`：

- `GET_ALL_RULES` 返回和旧 `RuleServer::GetAssembledJson()` 等价。
- `GET_RULES` 返回和旧 `RuleServer::GetAmsiRulesJson()` 等价。
- unknown command 返回 false。
- `InvalidateRuleCache()` 后下一次请求重新构建。

如果旧 `RuleServer` 行为不便直接比较，使用 golden fixture：

- 输入固定 `rasp_rules.json`。
- 断言返回 JSON 语义一致。
- 对关键字段做断言：`rules`、`globalLibrariesBase64`、`scriptEncoding`、`scriptBodyBase64`。

### 10.2 host adapter 测试

扩展 `amsi_ipc_host_adapter_tests.cpp`：

- 注入 fake rule provider。
- 启动 `AmsiIpcHost(config, adapters)`。
- 向 `amsi_detect_rules` 写 `GET_ALL_RULES\n`。
- 断言返回 fake provider 的 JSON。
- 断言 `rulesPath` 不参与响应。

注意：

- 使用真实 fixed pipe 名的测试可能与本机运行中的 `rasp_sentry.exe` 冲突。
- CI 中如果不稳定，应作为 integration test 单独运行。

### 10.3 回归测试

必须继续通过：

- `amsi_rule_channel_tests.exe`
- `amsi_event_channel_tests.exe`
- `amsi_control_status_channel_tests.exe`
- `amsi_ipc_host_adapter_tests.exe`
- `rasp_sentry.exe` Release build

## 11. 静态边界检查建议

Batch 5d 后建议增加 grep 门禁：

`DemoFileRuleProvider` 禁止：

- `CreateNamedPipeW`
- `ConnectNamedPipe`
- `NamedPipeServerPool`
- `AmsiRuleChannel`
- HostGuard / EDR SDK

`AmsiRuleChannel` 禁止：

- 规则文件路径
- `CompileAllRulesToBytecode`
- `InlineGlobalLibraries`
- `InlineScriptFiles`
- `nlohmann::json`

`AmsiIpcHost` 允许：

- 持有 channel / pool
- 选择 demo provider 或 injected provider

`AmsiIpcHost` 禁止：

- 解析规则 JSON
- 编译 Lua bytecode
- 读取规则文件内容

## 12. 风险与缓解

| 风险 | 说明 | 缓解 |
|---|---|---|
| 拆分后规则响应漂移 | `GET_ALL_RULES` / `GET_RULES` 结果变化 | golden fixture / 语义一致测试 |
| provider 生命周期悬挂 | pipe worker 持有 provider 引用 | Stop 先停 pool，再销毁 provider |
| HostGuard 过早依赖 demo watcher | 规则更新路径混乱 | injected provider 模式默认不启动 demo ConfigWatcher |
| bytecode 编译语义变化 | DLL 端加载 bytecode 失败 | 保留原 `CompileAllRulesToBytecode()` 逻辑原样迁移 |
| 一次改动过大 | RuleServer、ConfigWatcher、Host 同时变化 | 分 5d-1 / 5d-2 实施 |

## 13. 建议实施批次

### Batch 5d-1：设计和 provider 抽离

允许：

- 新增 `DemoFileRuleProvider`。
- 从 `RuleServer` 搬迁规则文件读取/cache/组装逻辑。
- 保持 `RuleServer` 作为兼容 wrapper。
- 增加 provider 单测。

禁止：

- 不改 `AmsiIpcHost` rules pipe 生命周期。
- 不改 `ConfigWatcher`。

### Batch 5d-2：AmsiIpcHost 接管 rules pipe

允许：

- `AmsiIpcHostAdapters` 增加 `ruleProvider`。
- `AmsiIpcHost` 统一创建 `AmsiRuleChannel` / `NamedPipeServerPool`。
- 未注入时使用 `DemoFileRuleProvider`。
- 注入时使用外部 provider。

禁止：

- 不改 DLL。
- 不改 wire 语义。
- 不接 HostGuard SDK。

### Batch 5d-3：ConfigWatcher provider 化

允许：

- `ConfigWatcher` 从 `RuleServer*` 改为 `IAmsiRuleProvider*`。
- demo mode 下继续 `InvalidateRuleCache()` + reload broadcast。
- injected ruleProvider mode 默认禁用 demo watcher。

禁止：

- 不让 ConfigWatcher 读取 HostGuard 内部状态。
- 不让 ConfigWatcher 依赖 HostGuard SDK。

## 14. 验收标准

Batch 5d 通过标准：

- demo mode 下 `rasp_sentry.exe` 行为不变。
- DLL 仍可通过 `amsi_detect_rules` 拉取规则。
- `GET_ALL_RULES` / `GET_RULES` 语义不变。
- `rulesPath` 仍可作为 demo fallback。
- injected rule provider 可返回规则 JSON。
- injected provider 模式不依赖 `rulesPath`。
- `AmsiRuleChannel` 仍只做 transport。
- `DemoFileRuleProvider` 不创建 pipe。
- `AmsiIpcHost` 不解析规则 JSON。
- 回归测试通过。

## 15. 当前建议

当前只保存本设计，等待评审。

不建议直接开工实现 5d，因为 5d 会触碰规则主链路和 reload 触发路径，应先评审以下点：

- 是否接受 `DemoFileRuleProvider` 命名。
- 是否保留 `RuleServer` 作为兼容 wrapper。
- injected `ruleProvider` 模式下是否默认禁用 `ConfigWatcher`。
- provider 单测使用 golden fixture 还是旧路径对比。
- 是否把 Batch 5d 拆成 5d-1 / 5d-2 / 5d-3 三个提交。
