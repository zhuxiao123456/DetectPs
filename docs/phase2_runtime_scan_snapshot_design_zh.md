# Phase 2 运行时、ScanGuard 和快照设计

## 范围

Phase 2 是架构安全修复。首批实施范围仅限于：

1. EngineRuntime 状态机。
2. ScanGuard 和活跃扫描计数。
3. RuleSnapshot 通过 `shared_ptr<const RuleSnapshot>` 发布。

首批不得更改 Lua 超时行为、PCRE2 限制、事件队列、会话缓存或采样窗口。

## EngineRuntime 边界

`EngineRuntime` 仅拥有运行时协调：

- `EngineState`
- `AmsiRuleEngine` 生命周期
- `active_scan_count`
- `ScanGuard`
- reload、shutdown 和 unload 协调
- 状态遥测

不得拥有：

- AMSI 流提取
- Lua 规则执行
- PCRE2 细节
- 采样归一化
- 事件 JSON 构建
- 规则 JSON 解析

## EngineState

```cpp
enum class EngineState {
    Uninitialized,
    Initializing,
    Ready,
    Reloading,
    Stopping,
    Inert,
    Stopped,
    Faulted
};
```

首批允许的转换：

```text
Uninitialized -> Initializing -> Ready
Ready -> Stopping -> Inert
Ready -> Inert
Initializing -> Faulted
Faulted -> Inert
```

保留给后续批次：

```text
Ready -> Reloading -> Ready
Reloading -> Stopping
Stopping -> Stopped
Inert -> Stopped
```

优先级：

- `Inert` 拒绝所有业务操作。
- `Stopping` 拒绝新扫描。
- `Faulted` 拒绝复杂逻辑，不得自动重试。
- `Ready` 是唯一允许扫描进入的状态。
- `Stopped` 是终态。

## 扫描热路径

`Scan()` 进入运行时的时间仅够：

1. 检查状态。
2. 递增 `active_scan_count`。
3. 获取本地引擎指针。
4. 退出运行时锁。

`Scan()` 不得在以下操作期间持有运行时互斥锁：

- 执行 Lua
- 执行 PCRE2
- 写管道
- 等待 sentry
- 输出阻塞日志

## 关闭排水

`BeginShutdown()` 必须：

1. 将运行时切换到 `Stopping` 或 `Inert`。
2. 拒绝新扫描。
3. 等待 `active_scan_count` 并有超时上限。
4. 超时时进入 `Inert` 并输出 `shutdown_drain_timeout`。

关闭不得无限等待。

## 快照发布

`RuleSnapshot` 以 `std::shared_ptr<const RuleSnapshot>` 发布。

规则：

- `Evaluate()` 在开头加载本地 `shared_ptr`。
- 本地快照在整个扫描期间保持有效。
- Reload 在发布前构建完整的下一个快照。
- Reload 失败保留旧快照。
- 已发布快照不可变。
- 旧快照不得手动删除。

## 首批验收

构建：

- 成功产出 `rasp_mod_amsi.dll`。
- 无新增生命周期或并发相关警告。
- 无新增链接器错误。

代码：

- 业务代码不得直接读取 `g_engine`。
- `CreateInstance`、`Scan` 和 `OnUnloadSignal` 通过 `EngineRuntime`。
- `ScanGuard` 在析构函数中释放 `active_scan_count`。
- `BeginShutdown` 使后续 `TryEnterScan` 调用失败。
- `WaitForActiveScansToDrain` 有上限。
- `RuleSnapshot` 无手动删除路径。
- `Evaluate()` 持有本地 `shared_ptr<const RuleSnapshot>`。

并发：

- 扫描加 reload 不崩溃。
- 扫描加关闭不崩溃。
- 关闭拒绝新扫描。
- inert 状态不进入复杂逻辑。
- reload 失败保留旧快照。