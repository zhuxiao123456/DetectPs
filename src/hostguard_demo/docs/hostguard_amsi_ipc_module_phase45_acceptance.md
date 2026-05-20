# HostGuard AMSI IPC Module Phase 4.5 验收说明

本文记录商业版 HostGuard 运行模型模拟的验收入口、故障注入覆盖和后续生产迁移缺口。

## 本阶段目标

- 在 `HostGuardAmsiIpcModule` 层补齐可读状态导出。
- 提供模块级运行时控制入口，覆盖 `status`、`reload-rules`、`pause-detection`、`resume-detection`、`dump-diag`。
- 通过单测模拟商业版依赖失败和生命周期边界。
- 保持 `HostGuardAmsiIpcAdapter` 只做通信适配，不把业务逻辑塞回 adapter。

## 新增状态接口

`HostGuardAmsiIpcModule::ExportStatusText()` 输出：

- module initialized / started
- module policyEnabled / policyVersion
- module lastError
- adapter lifecycleState / started / productionPipes
- adapter detectionEnabled
- adapter rule version / hash
- adapter event/status/rule 计数
- adapter drop/unknown/drain-ack 计数
- lastReload / lastPolicyBroadcast / lastUnload summary

`HostGuardAmsiIpcModule::GetStatus()` 仍保留结构化状态，便于真实 HostGuard 后续入库或上报。

## 新增控制入口

`HostGuardAmsiIpcModule::RunControlCommand(command, timeoutMs)` 当前支持：

- `status`：返回 `ExportStatusText()`。
- `reload-rules`：调用 `ReloadRules()`。
- `pause-detection`：调用 `ApplyPolicy(false, "manual-policy-disabled", timeoutMs)`。
- `resume-detection`：调用 `ApplyPolicy(true, "manual-policy-enabled", timeoutMs)`。
- `dump-diag`：返回 adapter diag ring 当前内容。

该入口用于 demo/commercial simulation 和测试，不改变 DLL wire protocol，也不新增 `GET_POLICY`。

## 故障注入测试

`hostguard_amsi_ipc_module_tests.exe` 覆盖：

- ruleProvider 失败：`Start()` 返回失败并记录 `lastError`。
- loadPolicy 失败：捕获异常，`Start()` 返回失败并记录 `lastError`。
- adapter Start 失败：通过 `HostGuardModuleContext::beforeAdapterStartForTest` 注入启动失败。
- adapter Reload 失败：real IPC 未 Start 时调用 `ReloadRules()`，返回失败。
- PauseDetection 失败但 `detectionEnabled=false` 仍保存。
- `Stop()` / `UnInit()` 重复调用幂等。
- callback 正在执行时 `Stop()` 会等待 in-flight callback 返回。
- `status/reload-rules/pause-detection/resume-detection/dump-diag` 控制入口。

`beforeAdapterStartForTest` 只用于测试/故障注入。真实 HostGuard 迁移时必须保持为空。

## 测试命令

构建并运行 module 测试：

```powershell
cmake --build build-hostguard-demo --target hostguard_amsi_ipc_module_tests --config Debug
.\build-hostguard-demo\Debug\hostguard_amsi_ipc_module_tests.exe
```

建议同时运行现有回归：

```powershell
cmake --build build-hostguard-demo --target hostguard_demo_options_tests --config Debug
.\build-hostguard-demo\Debug\hostguard_demo_options_tests.exe

cmake --build build-hostguard-demo --target hostguard_demo_smoke_tests --config Debug
.\build-hostguard-demo\Debug\hostguard_demo_smoke_tests.exe

cmake --build build-hostguard-demo --target hostguard_amsi_ipc_adapter_tests --config Debug
.\build-hostguard-demo\Debug\hostguard_amsi_ipc_adapter_tests.exe
```

真实 IPC manual smoke：

```powershell
cmake --build build-hostguard-demo --target hostguard_amsi_ipc_adapter_runtime_smoke_tests --config Debug
.\build-hostguard-demo\Debug\hostguard_amsi_ipc_adapter_runtime_smoke_tests.exe
```

## Production Integration Gap List

真实 HostGuard 迁移前仍需补齐：

- `GET_POLICY` 或等价的新进程策略获取机制。
- AMSI provider register/unregister 生产流程。
- 正式 EDR event 转换与字段规范。
- 服务端上报、重试和失败审计。
- 磁盘可靠队列或 HostGuard 现有可靠投递机制对接。
- DLL wire protocol 的 broadcastId ack 扩展。
- control pipe security 的生产级独立校验。
- HostGuard 真实 rule manager 的原子规则快照接口。
- HostGuard 真实 policy manager 的版本号、审计和回滚语义。
- event/status/diagnostic bus 的容量、背压和监控指标。

## 已知限制

- 本阶段不接商业生产代码，只在 `hostguard_demo` 内模拟商业运行模型。
- 本阶段不改变 DLL 协议，旧 1 字节广播协议仍无法让 DLL 回带 broadcastId。
- `pause-detection` 只覆盖已加载 DLL；新 PowerShell 进程策略关闭语义仍留给后续 `GET_POLICY` 或 register/unregister 方案。
- `RunControlCommand()` 是 module 级辅助入口，不是 pipe 命令，也不是 DLL 对外协议。
