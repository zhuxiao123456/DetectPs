# HostGuard AMSI IPC 正式迁移准备方案

本文用于 Phase 5 正式迁移准备。当前阶段只固化迁移边界、接口契约、准入门禁和回滚方案；不接商业生产主流程，不修改 DLL wire protocol，不实现 `GET_POLICY`、AMSI provider register/unregister、正式 EDR event 转换、服务端上报或磁盘可靠队列。

## #1 当前可迁移资产

### 当前 demo 源路径

以下是当前 `hostguard_demo` 仓库内真实来源路径，正式迁移时应从这些路径复制或移植：

- `src/hostguard_demo/src/hostguard_amsi_ipc_adapter.h`
- `src/hostguard_demo/src/hostguard_amsi_ipc_adapter.cpp`
- `src/hostguard_demo/src/hostguard_amsi_ipc_module.h`
- `src/hostguard_demo/src/hostguard_amsi_ipc_module.cpp`

### 建议商业目标路径

商业 HostGuard 工程建议落到独立模块目录，避免和 demo glue 混在一起：

- `src/modules/amsi_ipc/hostguard_amsi_ipc_adapter.h`
- `src/modules/amsi_ipc/hostguard_amsi_ipc_adapter.cpp`
- `src/modules/amsi_ipc/hostguard_amsi_ipc_module.h`
- `src/modules/amsi_ipc/hostguard_amsi_ipc_module.cpp`

如商业工程已有模块规范，应按商业工程规范重命名目录，但必须保持 adapter/module 边界不混淆。

### 可迁移能力

`HostGuardAmsiIpcAdapter` 提供通信适配能力：

- adapter 生命周期：`Init()` / `Start()` / `Stop()`
- 真实 `AmsiIpcHost` runtime 封装
- rule pipe：`GET_RULES` / `GET_ALL_RULES`
- event pipe 分类：Detection / DllDiagnosticLog / DrainAck / Unknown
- status pipe 原样转发
- detection/status/DLL diagnostic log 三类 forwarder 隔离
- adapter diag ring 和 diag callback
- broadcast tracker 骨架
- `Reload()` / `PauseDetection()` / `ResumeDetection()` / `Unload()`
- `enableRealIpc=false` mock/生命周期自检模式
- `enableRealIpc=true` 真实 IPC 模式

`HostGuardAmsiIpcModule` 提供商业运行模型编排能力：

- 注入商业规则快照 provider
- 注入策略中心：`HostGuardModuleContext::loadPolicy`
- 注入业务总线：event / DLL diagnostic log / status / adapter diag
- `ReloadRules()`：重新读取规则、更新 adapter 规则快照、广播 reload
- `ApplyPolicy()`：更新检测开关、广播 pause/resume
- `Unload()`：广播 unload
- `GetStatus()`：结构化状态
- `ExportStatusText()`：可读状态文本
- `RunControlCommand()`：本地受控管理入口

### 可迁移测试资产

以下测试建议作为迁移后的回归基线参考：

- `src/hostguard_demo/tests/hostguard_amsi_ipc_adapter_tests.cpp`
- `src/hostguard_demo/tests/hostguard_amsi_ipc_adapter_runtime_smoke_tests.cpp`
- `src/hostguard_demo/tests/hostguard_amsi_ipc_module_tests.cpp`

迁移到商业 HostGuard 后，应保留同等覆盖，但测试依赖需要替换为商业工程自己的 rule/policy/event/status/diag mock。

## #2 不应迁移的 demo/test-only 内容

### demo-only 文件

以下文件属于 `hostguard_demo` glue，不应直接进入商业生产主流程：

- `src/hostguard_demo/src/main.cpp`
- `src/hostguard_demo/src/hostguard_demo_app.h`
- `src/hostguard_demo/src/hostguard_demo_app.cpp`
- `src/hostguard_demo/src/hostguard_demo_options.h`
- `src/hostguard_demo/src/hostguard_demo_options.cpp`
- `src/hostguard_demo/src/hostguard_command_loop.h`
- `src/hostguard_demo/src/hostguard_command_loop.cpp`
- `src/hostguard_demo/src/hostguard_pipe_client.h`
- `src/hostguard_demo/src/hostguard_pipe_client.cpp`
- `src/hostguard_demo/src/hostguard_demo_pipe_client.cpp`
- `src/hostguard_demo/src/hostguard_jsonl_event_sink.h`
- `src/hostguard_demo/src/hostguard_jsonl_event_sink.cpp`
- `src/hostguard_demo/src/hostguard_jsonl_control_status_sink.h`
- `src/hostguard_demo/src/hostguard_jsonl_control_status_sink.cpp`

这些文件可以作为接入顺序和手工联调参考，但不应作为商业 HostGuard 的生产实现。

### demo 规则文件 provider

`src/hostguard_demo/src/hostguard_file_rule_provider.h/.cpp` 是 demo 文件规则来源。商业 HostGuard 应实现自己的商业规则快照 provider，不应依赖 `rasp_rules.json` 文件读取逻辑。

### 生产编译不得暴露的 API/字段

以下内容不得作为商业生产 API 暴露：

- `HostGuardModuleContext::beforeAdapterStartForTest`
- `InjectRawEventForTest()`
- `InjectStatusForTest()`
- mock-only runtime 注入入口
- demo command loop
- demo pipe client

`enableRealIpc=false` 可以保留为测试/生命周期自检模式，但它不是生产检测模式，也不应被解释为“生产已启用 AMSI IPC”。

### test-only hook 的生产隔离方式

正式迁移时必须二选一：

1. 使用 `UNIT_TEST` / `HOSTGUARD_TESTING` 宏包裹 `beforeAdapterStartForTest`，生产构建不编译该字段。
2. 拆分 `HostGuardModuleTestContext`，生产 `HostGuardModuleContext` 不包含该字段。

推荐方案 2：拆分测试 context。这样商业生产代码无法误用测试 hook 作为业务扩展点。

### 不应迁移的行为

- demo 命令行参数作为生产配置来源。
- 控制台 `status/reload/unload/quit` 作为生产控制面。
- JSONL 文件作为最终 EDR 事件处理。
- demo 自计算 FNV hash 作为商业规则版本真相源。
- demo pipe client 作为生产组件。
- demo pipe 名作为正式通信名。

## #3 商业 HostGuard 映射表

| 当前 demo/module/adapter 资产 | 商业 HostGuard 对应模块 | 迁移方式 | 说明 |
| --- | --- | --- | --- |
| `HostGuardAmsiIpcAdapter` | AMSI IPC 通信适配层 | 直接复用 | 只负责 IPC、队列、forwarder、broadcast，不承载业务转换 |
| `HostGuardAmsiIpcModule` | AMSI IPC 业务编排层 | 直接复用或轻量封装后复用 | 负责把商业规则/策略/总线注入 adapter |
| `ICommercialAmsiRuleSnapshotProvider` | 商业规则中心 | 新增商业接口 | 向 module 提供 allRulesJson、amsiRulesJson、version、hash 原子快照 |
| `amsi_ipc::IAmsiRuleProvider` | rule pipe 响应接口 | adapter 内部/兼容接口 | 只表达 `GET_RULES` / `GET_ALL_RULES` 响应，不足以单独承载 version/hash |
| `HostGuardModuleContext::loadPolicy` | 商业策略中心 | 重写实现 | 返回当前 detection enabled 和 policy version |
| `eventBus` | EDR event pipeline | 重写实现 | callback 内只投递，不做阻塞转换 |
| `dllDiagnosticLogBus` | DLL 诊断日志队列 | 重写实现 | 区分 DLL log 与 adapter 自身 diag |
| `statusBus` | DLL 实例/规则加载状态总线 | 重写实现 | 处理 `DLL_LOADED`、`RULE_LOAD_RESULT` 等状态 |
| `diagLogger` | HostGuard 自诊断日志 | 重写实现 | 记录 adapter/module 自身诊断 |
| `RunControlCommand()` | 本地受控管理入口 | 可选复用 | 只能接受鉴权的本地管理面，不得暴露给 DLL |
| `HostGuardDemoApp` | HostGuard service init/uninit | 不迁移 | 只参考调用顺序 |

## #4 生命周期映射

### 商业 HostGuard 启动

推荐映射：

```cpp
HostGuard service init
  -> 构造 HostGuardAmsiIpcModule
  -> 构造 HostGuardAmsiIpcConfig
  -> 构造 HostGuardModuleContext
  -> module.Init(config, context, error)
  -> module.Start(error)
```

### `Init()`

商业语义：

- 只做内存对象初始化、依赖注入、callback 绑定。
- 不执行重业务。
- 不执行长时间 IO。
- 不在 callback 内捕获会早于 `module.Stop()` 销毁的对象。

失败处理：

- `Init()` 失败时，不调用 `Start()`。
- HostGuard 应记录 fatal 或 degraded 状态。
- 如果配置要求 AMSI IPC 必须启用，HostGuard 应拒绝进入正常运行态。

### `Start()`

商业语义：

- 从商业规则中心读取当前原子规则快照。
- 从商业策略中心读取当前策略快照。
- 调用 `adapter.UpdateRules(allRulesJson, amsiRulesJson, version, hash)`。
- 调用 `adapter.SetDetectionEnabled()`。
- 启动真实 IPC runtime。

失败处理：

- `Start()` 失败时，调用 `module.Stop()` 做资源回收。
- 不应继续向 DLL 宣称 AMSI IPC 已可用。
- 失败原因写入 HostGuard diag 和健康状态。

### `Stop()` / `UnInit()`

商业语义：

```cpp
HostGuard service uninit
  -> module.Stop()
  -> module.UnInit()
  -> 销毁 callback 捕获对象和业务队列
```

约束：

- `Stop()` 必须先于业务队列和 callback 捕获对象销毁。
- `Stop()` 返回后，不应再触发 HostGuard callback。
- callback 内禁止同步反调 `Stop/Start/Reload/Unload/PauseDetection/ResumeDetection`。
- 如 callback 需要触发控制动作，必须投递到 HostGuard 控制线程异步执行。

### 运行时操作

规则更新：

```cpp
module.ReloadRules(timeoutMs, error);
```

策略关闭：

```cpp
module.ApplyPolicy(false, policyVersion, timeoutMs, error);
```

策略开启：

```cpp
module.ApplyPolicy(true, policyVersion, timeoutMs, error);
```

卸载：

```cpp
module.Unload(timeoutMs, error);
```

## #5 规则/策略/事件/status/diag 接口契约

### 商业规则快照接口

商业 HostGuard 应在 module 上层提供明确的规则快照接口：

```cpp
struct CommercialAmsiRuleSnapshot {
    std::string allRulesJson;
    std::string amsiRulesJson;
    std::string version;
    std::string hash;
};

class ICommercialAmsiRuleSnapshotProvider {
public:
    virtual ~ICommercialAmsiRuleSnapshotProvider() = default;

    virtual bool LoadSnapshot(CommercialAmsiRuleSnapshot& out,
                              std::string& error) = 0;

    virtual void InvalidateRuleCache() = 0;
};
```

契约区分：

- `ICommercialAmsiRuleSnapshotProvider` 是商业规则中心到 module 的快照接口。
- `amsi_ipc::IAmsiRuleProvider` 是 adapter/rule pipe 响应接口。
- 二者可以由同一个商业对象实现，但语义必须区分。
- `IAmsiRuleProvider::BuildRulesResponse()` 当前只返回 JSON，不携带完整 `version/hash`，不能单独作为 module 规则快照真相源。

快照要求：

- `allRulesJson`、`amsiRulesJson`、`version`、`hash` 必须来自同一个原子规则快照。
- `UpdateRules()` 成功后才能广播 `Reload()`。
- `UpdateRules()` 失败时保留旧规则快照。
- `hash/version` 由商业规则中心生成，通信层不重新计算业务 hash。
- 空规则如果是合法业务状态，必须仍有合法 version/hash。
- 规则未就绪时，应返回明确错误，不应返回空 JSON 伪装成功。

### Rule pipe 响应接口

adapter/rule pipe 侧仍使用：

```cpp
class CommercialAmsiRuleProvider final : public amsi_ipc::IAmsiRuleProvider {
public:
    bool BuildRulesResponse(const std::string& command,
                            amsi_ipc::AmsiRuleResponse& out,
                            std::string& error) override;

    void InvalidateRuleCache() override;
};
```

命令语义：

- `GET_RULES` 返回 AMSI DLL 需要的规则 JSON。
- `GET_ALL_RULES` 返回完整规则 JSON。
- 未知命令返回失败，错误语义为 unsupported command。

### 策略中心契约

商业策略中心向 module 提供：

```cpp
HostGuardPolicySnapshot{
    detectionEnabled,
    policyVersion
}
```

要求：

- `policyVersion` 必须可审计、可关联策略变更记录。
- `detectionEnabled=false` 时，`ApplyPolicy(false)` 必须先保存 adapter/module 当前策略状态，再广播 pause。
- pause 广播失败时，当前策略真相仍为 disabled，并记录部分失败风险。
- 本阶段不覆盖策略关闭后新启动 PowerShell 的语义；该语义后续通过 `GET_POLICY` 或 register/unregister 方案补齐。

### Detection event 总线契约

`eventBus` 输入：

```cpp
void(const HostGuardAmsiEventEnvelope& event)
```

要求：

- callback 只做轻量投递到商业 event queue。
- 不在 callback 内执行 EDR 转换、入库、网络上报或复杂 JSON 处理。
- 生产 EDR event 转换由 HostGuard 后续 pipeline 完成。
- 队列满、转换失败、上报失败应由 HostGuard 业务层计数和审计。

### DLL diagnostic log 总线契约

`dllDiagnosticLogBus` 输入：

```cpp
void(const HostGuardAmsiEventEnvelope& log)
```

要求：

- 只承载 DLL 发来的 diagnostic/log payload。
- 不与 adapter 自身 diag 混用。
- 可降级丢弃低价值 debug log，但必须计数。
- 如果商业 HostGuard 需要本地文件日志，应由商业日志模块处理，不由 adapter 写盘。

### Status 总线契约

`statusBus` 输入：

```cpp
void(const std::string& rawStatus)
```

要求：

- callback 只投递 raw status。
- DLL 实例状态、规则加载结果、policy ack 等解析由 HostGuard status pipeline 完成。
- `RULE_LOAD_RESULT` 应能合并到 DLL instance 视图。
- status 队列不建议静默丢弃关键状态；满载时应进入 degraded 并记录 lastError 或覆盖同 instance 的旧状态。

### Adapter diag 契约

`diagLogger` 输入：

```cpp
void(const HostGuardAmsiAdapterDiag& diag)
```

要求：

- 只承载 adapter/module 自身诊断。
- 记录 pipe 启停、队列丢弃、未知 event、broadcast 失败、late ack、security TODO 等。
- 不承载 DLL diagnostic log。

### `RunControlCommand()` 暴露边界

`RunControlCommand()` 能触发 reload、pause、resume、diag dump 等高风险动作，只能绑定到受控管理面：

- 本地管理员 CLI。
- HostGuard 内部控制总线。
- 受鉴权的运维通道。

不得暴露到：

- DLL IPC 输入。
- event/status pipe。
- 未鉴权本地用户。
- 远程未授权接口。

## #6 配置与灰度开关

### 生产配置项

建议商业 HostGuard 配置中心提供：

```cpp
amsiIpc.enabled
amsiIpc.enableRealIpc
amsiIpc.useProductionPipes
amsiIpc.rulePipeThreads
amsiIpc.eventPipeThreads
amsiIpc.statusPipeThreads
amsiIpc.detectionEventQueueCapacity
amsiIpc.detectionEventQueueMaxBytes
amsiIpc.dllDiagnosticLogQueueCapacity
amsiIpc.dllDiagnosticLogQueueMaxBytes
amsiIpc.statusQueueCapacity
amsiIpc.statusQueueMaxBytes
amsiIpc.stopTimeoutMs
amsiIpc.broadcastTimeoutMs
```

### 初始默认关闭策略

正式迁移初期建议：

- `amsiIpc.enabled=false`
- `amsiIpc.enableRealIpc=false`
- `amsiIpc.useProductionPipes=false`

`useProductionPipes` 只有在 `enabled=true` 且 `enableRealIpc=true` 时才生效。预生产/生产灰度时再显式设置：

```text
amsiIpc.useProductionPipes=true
```

灰度阶段按顺序开启：

1. 内部测试环境：`enabled=true`，`enableRealIpc=false`，验证 module 依赖注入和状态。
2. 独立联调环境：`enabled=true`，`enableRealIpc=true`，使用 demo pipe，避免占用正式 pipe。
3. 预生产环境：`enabled=true`，`enableRealIpc=true`，`useProductionPipes=true`，确认无其他服务端占用正式 pipe。
4. 小流量生产：开启正式 pipe，监控 event/status/diag 计数和 broadcast 失败率。
5. 扩大生产范围：仅在准入门禁全部通过后执行。

### 严格模式要求

`useProductionPipes=true` 时必须严格使用正式 pipe 名：

- 不允许静默 fallback 到 `_demo` pipe。
- 正式 pipe 被占用时必须失败并记录明确错误。
- 状态输出必须展示当前 pipe mode 和 production pipe 使用状态。

## #7 Pipe security 审计要求

### control/config pipe

control/config pipe 可触发 reload/unload/pause/resume，必须作为高风险接口审计。

最终生产要求：

- 只允许 `SYSTEM`、`Administrators`、HostGuard 服务身份访问。
- 禁止 `Everyone` 写。
- 禁止 `Authenticated Users` 写。
- 安全描述符创建失败时，`Start()` 必须失败。
- 权限校验结果必须写入 adapter diag 和 HostGuard 安全审计日志。

### rule pipe

rule pipe 面向 DLL 规则拉取，要求：

- 只允许预期 DLL 运行身份读取。
- 禁止低权限非预期本地用户枚举或拉取规则。
- 超大响应必须受 `maxRuleResponseBytes` 限制。
- 未知命令必须计数并审计。

### event/status pipe

event/status pipe 面向 DLL 上报，要求：

- 限制单条 payload 大小。
- 限制队列条数和字节预算。
- 对非法、空、超大 payload 记录计数和 diag。
- 不在 pipe worker 中执行阻塞业务。

### enableRealIpc 前置硬门禁

在商业工程中允许 `enabled=true` 但 `enableRealIpc=false` 先行合入，用于验证 module 生命周期和依赖注入。

任何环境启用 `enableRealIpc=true` 前，必须完成 control/config pipe ACL 审计。也就是说，pipe security 可以按 commit 拆分落地，但不能晚于真实 IPC 启用。

### 当前缺口

当前 Phase 仍将部分 pipe security 校验委托给 `AmsiIpcHost`，尚未完成商业生产级独立审计。正式迁移 commit 中必须单独补齐，不应和业务接入混在一起。

## #8 正式迁移 commit 拆分

建议拆成以下提交，便于 review、回退和定位：

### Commit 1：引入 IPC adapter/module 源码

内容：

- 从当前 demo 源路径复制 adapter/module 文件。
- 落到商业目标模块目录。
- 添加必要 include/CMake/工程文件。
- 不接入 HostGuard service init。
- 拆分或宏隔离 `beforeAdapterStartForTest`。

验证：

- 只编译通过。
- mock adapter/module 单测通过。

### Commit 2：接入商业规则快照 provider

内容：

- 新增 `CommercialAmsiRuleSnapshot`。
- 新增 `ICommercialAmsiRuleSnapshotProvider`。
- 对接商业规则快照 version/hash。
- 保持 rule pipe 的 `IAmsiRuleProvider` 响应语义清晰。
- 补规则快照并发测试。

验证：

- `GET_RULES` / `GET_ALL_RULES` mock 测试。
- `UpdateRules()` 成功/失败回滚测试。
- version/hash/json 同源快照测试。

### Commit 3：接入商业策略中心

内容：

- 实现 `loadPolicy`。
- 接入 `ApplyPolicy()`。
- 暂不实现 `GET_POLICY`。
- 暂不实现 register/unregister。

验证：

- policy enabled/disabled 单测。
- pause 失败但状态保存测试。

### Commit 4：接入商业 event/status/diag bus

内容：

- eventBus 只投递到商业事件队列。
- dllDiagnosticLogBus 只投递到 DLL log 队列。
- statusBus 只投递到状态队列。
- diagLogger 写 HostGuard 自诊断日志。

验证：

- callback 不阻塞 pipe worker。
- Stop 等待 in-flight callback。
- 队列满策略和计数。

### Commit 5：接入 HostGuard service init/uninit 灰度开关

内容：

- 配置默认关闭。
- service init 中按配置构造 module。
- service uninit 中 Stop/UnInit。
- 不改变原有主流程默认行为。

验证：

- `enabled=false` 原行为不变。
- `enabled=true enableRealIpc=false` mock 模式可启动。

### Commit 6：pipe security 生产审计

内容：

- control/config pipe DACL 明确校验。
- rule/event/status pipe 权限审计。
- 安全描述符失败时 Start 失败。
- 增加安全审计日志。

验证：

- 低权限访问拒绝测试。
- pipe 被占用失败测试。
- security diag 输出测试。

硬约束：

- 任意环境启用 `enableRealIpc=true` 前，Commit 6 必须完成。

### Commit 7：真实 IPC 灰度启用

内容：

- 允许指定环境设置 `enableRealIpc=true`。
- 保留默认关闭。
- 增加真实 IPC smoke/integration 脚本。
- 增加运行时状态 dump。
- 增加快速关闭开关和回滚文档。

验证：

- 一键执行准入测试。
- 关闭开关后不创建 IPC 服务端。

## #9 准入门禁

### 编译门禁

必须通过：

```powershell
cmake --build build-hostguard-demo --target hostguard_amsi_ipc_adapter_tests --config Release
cmake --build build-hostguard-demo --target hostguard_amsi_ipc_module_tests --config Release
cmake --build build-hostguard-demo --target hostguard_amsi_ipc_adapter_runtime_smoke_tests --config Release
```

商业工程中对应目标也必须通过 Release 构建。

### 单测门禁

必须覆盖：

- adapter Init/Start/Stop 状态机。
- module Init/Start/Stop/UnInit 状态机。
- rule snapshot provider 成功/失败。
- version/hash/json 同源快照。
- loadPolicy 成功/失败。
- `ReloadRules()` 成功/失败。
- `ApplyPolicy(false/true)` 成功/失败。
- Stop 后不再触发 callback。
- Stop 等待 in-flight callback。
- queue count limit 和 byte budget。
- Detection / DiagnosticLog / DrainAck / Unknown 分类。
- 生产构建不暴露 test-only hook。

### 真实 IPC smoke 门禁

必须覆盖：

- `enableRealIpc=true` 启动和 Stop。
- `GET_RULES\n` 返回 AMSI rules。
- `GET_ALL_RULES\n` 返回完整 rules。
- Detection event 进入 event bus。
- DLL diagnostic log 进入 log bus。
- status payload 进入 status bus。
- `Reload/PauseDetection/ResumeDetection/Unload` 能走 broadcaster。
- 旧协议无 broadcastId ack 时，不计入 `result.acked`。

### DLL 联调门禁

接真实 DLL 前必须确认：

- HostGuard 侧 `GET_RULES` / `GET_ALL_RULES` 已独立通过。
- event/status pipe 已独立通过。
- reload/unload/pause/resume 可重复执行，不挂死。
- 日志和状态可观测。
- `useProductionPipes=true` 时无 demo fallback。

### 安全门禁

必须确认：

- control/config pipe 不允许低权限用户写。
- 正式 pipe 被占用时明确失败。
- 超大 payload 被拒绝或丢弃并计数。
- callback 阻塞不会阻塞 pipe worker。
- Stop 后不会触发已销毁对象。
- `RunControlCommand()` 不暴露给 DLL、event/status pipe、未鉴权本地用户或远程未授权接口。

### 运维门禁

必须提供：

- 状态输出。
- diag dump。
- 最近一次 reload/pause/resume/unload result。
- dropped event/status/log 计数。
- 快速关闭开关。
- 回滚步骤。

## #10 回滚方案

### 配置回滚

第一优先级回滚方式：

```text
amsiIpc.enabled=false
```

效果：

- HostGuard 不创建 `HostGuardAmsiIpcModule`。
- 不启动 adapter。
- 不创建 rule/event/status/config pipe 服务端。
- 旧生产主流程保持原行为。

第二级回滚：

```text
amsiIpc.enableRealIpc=false
```

效果：

- module 可保留初始化。
- 不启动真实 IPC。
- 用于保留状态观测和验证依赖注入，但停止对 DLL 提供通信服务。

### 策略回滚

如果只需要停止检测而不停止 IPC：

```cpp
module.ApplyPolicy(false, rollbackPolicyVersion, timeoutMs, error);
```

注意：

- 当前阶段只影响已加载 DLL。
- 新进程策略关闭语义尚未由本阶段覆盖。
- 如生产要求覆盖新进程，必须依赖后续 `GET_POLICY` 或 register/unregister 方案。

### 代码回滚

按 commit 拆分回滚：

1. 优先回滚 HostGuard service init/uninit 接入 commit。
2. 如问题来自 pipe security，单独回滚 pipe security commit。
3. 如问题来自 bus 对接，单独回滚 event/status/diag bus commit。
4. 尽量保留 adapter/module 源码 commit，避免影响后续离线修复和测试。

### 运行时回滚检查

回滚后必须确认：

- 正式 pipe 不再由新 module 占用。
- HostGuard 旧主流程状态正常。
- 没有残留 IPC worker 线程。
- 没有 Stop 后 callback。
- diag 中记录回滚原因、时间、配置版本。

### 数据和审计

回滚不应删除已有 event/status/diag 数据。商业 HostGuard 应记录：

- 回滚触发人或触发策略。
- 回滚前 `ExportStatusText()` 快照。
- 最近一次 broadcast result。
- 最近 dropped 计数。
- 最近 lastError。
