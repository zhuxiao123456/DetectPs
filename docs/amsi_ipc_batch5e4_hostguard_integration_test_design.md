# Batch 5e-4 HostGuard-style Integration Test Design

## 1. 目标

验证 HostGuard 未来可以只依赖 `AmsiIpcHost` 和三个注入接口托管 AMSI IPC：

- `IAmsiRuleProvider`
- `IAmsiEventSink`
- `IAmsiControlStatusSink`

本批不接 HostGuard SDK，不改 DLL，不改生产默认 pipe 名。

## 2. 关键约束

### 2.1 测试 pipe 必须隔离

真实 named pipe 测试不能直接使用生产 `amsi_detect_*` 名称，否则会和本机正在运行的 `rasp_sentry.exe` 或测试机 demo 冲突。

本批给 `AmsiIpcHostConfig` 增加可选 pipe name override：

- `rulesPipeName`
- `eventsPipeName`
- `controlStatusPipeName`
- `configPipeName`

字段为空时继续使用生产默认 pipe 名。

### 2.2 Broadcast 断言不能假设真实环境无 listener

只有测试使用独立 `configPipeName` 且未启动 listener 时，才允许断言 `reached == 0`。

普通生产环境或共享测试机不应把 `reached == 0` 写成通用断言。

### 2.3 Rules pipe 必须覆盖两个命令

HostGuard-style 测试必须覆盖：

- `GET_RULES`
- `GET_ALL_RULES`

两者 wire 语义不同，不能只测一个。

### 2.4 Sink 必须验证 payload 原样透传

event / control status sink 测试必须断言：

- 不追加换行
- 不改 UTF-8 字节
- 不做 JSON parse/rewrite
- payload 完全相等

测试 payload 应包含中文或 emoji，锁定 UTF-8 透传行为。

## 3. 实施分批

### Batch 5e-4a：pipe name override

修改：

- `AmsiIpcHostConfig`
- `AmsiIpcHost::Start()`
- `AmsiIpcHost::BroadcastReload()`
- `AmsiIpcHost::BroadcastUnload()`

行为：

- 默认 pipe 名不变。
- 测试可传入自定义 pipe 名。
- `rasp_sentry.exe` demo 不需要改调用代码。

### Batch 5e-4b：HostGuard-style integration test

新增测试：

- `src/amsi_ipc_host/tests/amsi_ipc_hostguard_integration_tests.cpp`

测试内容：

- 禁用 demo watcher。
- 注入 fake rule provider。
- 注入 fake event sink。
- 注入 fake control status sink。
- 使用测试专用 pipe 名。
- `GET_RULES` 返回 fake AMSI rules。
- `GET_ALL_RULES` 返回 fake assembled rules。
- event payload 原样进入 fake event sink。
- control status payload 原样进入 fake status sink。
- `InvalidateRules()` 调用 fake provider。
- `BroadcastReload()` / `BroadcastUnload()` 可调用且返回结果。

## 4. 禁止项

- 不改生产默认 pipe 名。
- 不改 DLL。
- 不改 pipe wire protocol。
- 不接 HostGuard SDK。
- 不删除 `RuleServer`。
- 不改 demo `rasp_sentry.exe` 默认行为。

## 5. 验收标准

- 默认 `rasp_sentry.exe` 仍使用生产 `amsi_detect_*` pipe。
- HostGuard-style 测试使用唯一测试 pipe 名，不依赖本机 demo 是否运行。
- `GET_RULES` / `GET_ALL_RULES` 都走 injected provider。
- event / control status payload 原样透传。
- `InvalidateRules()` 和 config broadcaster façade 可用。
- 现有 5d/5e 回归测试继续通过。
