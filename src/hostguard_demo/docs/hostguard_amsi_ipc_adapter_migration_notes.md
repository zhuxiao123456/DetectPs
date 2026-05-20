# HostGuard AMSI IPC Adapter 迁移说明

本文记录 Phase 3 后续迁移到真实 HostGuard 业务程序时，哪些代码可以直接复用，哪些 demo glue 需要重写。

## 迁移结论

核心结论：

- `HostGuardAmsiIpcAdapter` 是可复用通信适配层，建议直接搬到 HostGuard 工程。
- `HostGuardDemoApp` 是 demo glue，只适合作为接入顺序参考，不建议直接搬到生产业务。
- demo 的文件规则读取、JSONL 落盘、命令行解析、手工命令循环、pipe client 都不应成为真实 HostGuard 业务依赖。

## 可直接复用的文件

建议直接复用：

- `src/hostguard_amsi_ipc_adapter.h`
- `src/hostguard_amsi_ipc_adapter.cpp`

这两个文件封装了：

- adapter 生命周期状态机
- 真实 `AmsiIpcHost` runtime 包装
- rule pipe provider
- event/status/DLL diagnostic log 队列和 forwarder
- adapter diag ring/callback
- broadcast tracker 骨架
- Reload / PauseDetection / ResumeDetection / Unload 控制接口
- mock 注入入口和 real IPC 开关

真实 HostGuard 调用的主要接口：

```cpp
HostGuardAmsiIpcAdapter adapter;

adapter.Init(config, error);
adapter.SetDetectionEventCallback(...);
adapter.SetDllDiagnosticLogCallback(...);
adapter.SetStatusCallback(...);
adapter.SetAdapterDiagCallback(...);
adapter.UpdateRules(allRulesJson, amsiRulesJson, version, hash, error);
adapter.SetDetectionEnabled(policyEnabled, policyVersion, error);
adapter.Start(error);

adapter.Reload(timeoutMs, result);
adapter.PauseDetection(timeoutMs, result);
adapter.ResumeDetection(timeoutMs, result);
adapter.Unload(timeoutMs, result);

adapter.GetStatus();
adapter.GetRecentAdapterDiag();
adapter.Stop();
```

## HostGuard 需要重写的文件和函数

以下文件属于 demo 层，不建议直接搬到真实业务：

- `src/hostguard_demo_app.h`
- `src/hostguard_demo_app.cpp`
- `src/hostguard_demo_options.cpp`
- `src/hostguard_command_loop.cpp`
- `src/hostguard_pipe_client.cpp`
- `src/hostguard_demo_pipe_client.cpp`
- `src/hostguard_file_rule_provider.*`
- `src/hostguard_jsonl_event_sink.*`
- `src/hostguard_jsonl_control_status_sink.*`

其中 `HostGuardDemoApp` 内以下函数只作为迁移参考，需要在真实 HostGuard 中用业务模块重写：

- `HostGuardDemoApp::Start()`
- `HostGuardDemoApp::Stop()`
- `HostGuardDemoApp::Reload()`
- `HostGuardDemoApp::Unload()`
- `HostGuardDemoApp::PrintStatus()`
- `ParseHostGuardDemoOptions()`

## 真实 HostGuard 应替换的业务逻辑

### 1. 配置来源

demo 当前配置字段：

```cpp
amsiIpc.enabled
amsiIpc.enableRealIpc
amsiIpc.useProductionPipes
rulesPipeName
eventsPipeName
controlStatusPipeName
configPipeName
```

真实 HostGuard 应从自身配置中心或服务配置读取，不应复用 demo 命令行解析。

生产建议默认：

```cpp
enabled = true;
enableRealIpc = true;
useProductionPipes = true;
```

测试环境可显式使用 demo pipe，避免和正式服务冲突。

### 2. 规则来源

demo 当前通过 `HostGuardFileRuleProvider` 从 `rasp_rules.json` 读取并拆分：

- `GET_ALL_RULES` -> `allRulesJson`
- `GET_RULES` -> `amsiRulesJson`

真实 HostGuard 应由业务规则管理模块直接提供：

```cpp
struct AmsiRuleSnapshot {
    std::string allRulesJson;
    std::string amsiRulesJson;
    std::string version;
    std::string hash;
};
```

迁移要求：

- `version/hash/json` 必须是同一个原子快照。
- `UpdateRules()` 成功后再广播 `Reload()`。
- `UpdateRules()` 失败时保留旧规则快照。
- hash/version 由 HostGuard 业务规则模块生成，adapter 不重新计算业务 hash。

### 3. 策略状态来源

demo 当前固定调用：

```cpp
SetDetectionEnabled(true, "hostguard-demo-policy-enabled", error);
```

真实 HostGuard 应绑定实际策略状态：

```cpp
adapter.SetDetectionEnabled(policyEnabled, policyVersion, error);
```

策略关闭/开启时：

- 已加载 DLL：通过 `PauseDetection()` / `ResumeDetection()` 广播。
- 新进程加载 provider 的问题：本阶段仍不实现 `GET_POLICY`，也不实现 register/unregister。生产如果需要覆盖新进程，需要后续 Phase 单独设计。

### 4. 回调处理

demo 当前回调落到 JSONL：

- detection event -> `HostGuardJsonlEventSink`
- DLL diagnostic log -> `HostGuardJsonlEventSink`
- status -> `HostGuardJsonlControlStatusSink`
- adapter diag -> `SentryLog`

真实 HostGuard 应改成轻量投递：

- detection event -> HostGuard event bus / EDR pipeline
- DLL diagnostic log -> HostGuard diagnostic log queue
- status -> DLL 实例状态和规则加载结果处理模块
- adapter diag -> HostGuard 自诊断日志

硬约束：

- callback 内不做阻塞业务。
- callback 内不直接入库、上报、重解析大对象。
- callback 内不同步调用 `Stop/Start/Reload/Unload/PauseDetection/ResumeDetection`。
- callback 捕获对象必须在 `adapter.Stop()` 返回后再销毁。

### 5. 生命周期接入

真实 HostGuard 推荐封装一个业务模块：

```cpp
class HostGuardAmsiModule {
public:
    bool Init(const HostGuardConfig& config);
    bool Start();
    void UnInit();

    bool OnRulesUpdated(const AmsiRuleSnapshot& snapshot);
    bool OnPolicyChanged(bool enabled, const std::string& policyVersion);

    bool ReloadDllRules();
    bool PauseDetection();
    bool ResumeDetection();
    bool UnloadDll();

private:
    HostGuardAmsiIpcAdapter adapter_;
};
```

推荐启动顺序：

```cpp
adapter.Init(config, error);
adapter.SetDetectionEventCallback(...);
adapter.SetDllDiagnosticLogCallback(...);
adapter.SetStatusCallback(...);
adapter.SetAdapterDiagCallback(...);
adapter.UpdateRules(allRulesJson, amsiRulesJson, version, hash, error);
adapter.SetDetectionEnabled(policyEnabled, policyVersion, error);
adapter.Start(error);
```

推荐退出顺序：

```cpp
adapter.Stop();
// Stop 返回后再销毁 callback 捕获对象和业务队列。
```

### 6. Reload / Unload 接入

demo 当前 `Reload()` 在 adapter 分支中先重新读取文件规则，再 `UpdateRules()`，最后广播 `Reload()`。

真实 HostGuard 应改为：

```cpp
bool HostGuardAmsiModule::OnRulesUpdated(const AmsiRuleSnapshot& snapshot)
{
    if (!adapter_.UpdateRules(snapshot.allRulesJson,
                              snapshot.amsiRulesJson,
                              snapshot.version,
                              snapshot.hash,
                              error)) {
        return false;
    }
    return adapter_.Reload(timeoutMs, result);
}
```

`Unload()` 可直接转发：

```cpp
adapter_.Unload(timeoutMs, result);
```

## 不要迁移的 demo 行为

以下行为只用于 demo，不应成为生产 HostGuard 语义：

- 从本地 `rasp_rules.json` 直接读取规则。
- 用 demo 自己计算的 FNV-1a hash 作为生产规则 hash。
- 把 event/status 直接写 JSONL 当作最终业务处理。
- 使用控制台命令 `status/reload/unload/quit` 驱动生产流程。
- 使用 `hostguard_demo_pipe_client.exe` 作为生产组件。
- 依赖 demo pipe 名作为正式通信名。

## 当前 Phase 3 边界

已完成：

- demo 配置开关：
  - `amsiIpc.enabled`
  - `amsiIpc.enableRealIpc`
  - `amsiIpc.useProductionPipes`
- demo `Start()` 中初始化 adapter。
- demo `Stop()` 中停止 adapter。
- demo 向 adapter 注入规则和策略状态。
- demo 设置 detection / DLL diagnostic / status / adapter diag callback。
- demo smoke 覆盖 adapter mock 和 real IPC 分支。

未完成，后续 Phase 单独处理：

- `GET_POLICY`
- AMSI provider register/unregister
- EDR event 转换
- 服务端上报
- 磁盘可靠队列
- 新进程策略关闭语义
- 真实 HostGuard 生产 init/uninit 接入

## 推荐迁移步骤

1. 将 `hostguard_amsi_ipc_adapter.h/.cpp` 复制到 HostGuard 工程。
2. 补齐 `amsi_ipc_host`、pipe channel、broadcaster 等依赖源文件和 include 路径。
3. 在 HostGuard 中新增 `HostGuardAmsiModule`，内部持有 `HostGuardAmsiIpcAdapter`。
4. 用 HostGuard 配置中心替换 demo `HostGuardDemoOptions`。
5. 用 HostGuard 规则管理器替换 `HostGuardFileRuleProvider`。
6. 用 HostGuard event/log/status 队列替换 JSONL sink。
7. 在 HostGuard service init/uninit 中接入 `Init/Start/Stop`。
8. 增加生产侧 integration 测试，覆盖 rule/event/status/broadcast。
