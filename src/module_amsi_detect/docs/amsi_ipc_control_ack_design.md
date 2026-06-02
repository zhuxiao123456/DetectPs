# AMSI IPC 控制命令广播触达统计方案

## 1. 背景

当前 `AmsiIpcRuntime` 通过 `amsi_detect_config` 向已加载 DLL 广播 1 字节控制信号：

| 信号 | 含义 |
|---|---|
| `0x01` | reload |
| `0x02` | unload |
| `0x03` | pause detection |
| `0x04` | resume detection |

本阶段不引入复杂 ACK 协议。参考 `amsi_staging_watcher.cpp` 中 `BroadcastUnload()` / `WaitForDrainAck()` 的思路，先复用广播层返回的 `AmsiBroadcastResult.reached`，只回答一个问题：

> 本次控制命令广播到了多少个 DLL config pipe listener。

## 2. 设计目标

1. 不修改 DLL wire protocol。
2. 不新增 `CONTROL_ACK`。
3. 不新增 `broadcastId`。
4. `reload / unload / pause / resume` 都记录本次广播 `reached` 数量。
5. 日志和 `GetStats()` 可以看到最近一次四类命令的 `reached / lastError`。
6. `Unload` 后续可选参考 `WaitForDrainAck(reached, timeout)`，但本阶段不强制等待 drain ack。

## 3. reached 语义

`reached` 来自 `AmsiConfigBroadcaster::Broadcast()`：

```cpp
AmsiBroadcastResult result = broadcaster.Broadcast(signal, maxListeners, timeoutMs);
```

含义：本次广播过程中，Host 成功打开并写入控制字节的 DLL config pipe listener 数量。

它不是强 ACK：

- 不代表 DLL 已执行完成。
- 不代表规则已加载成功。
- 不代表检测已暂停或恢复完成。
- 不代表当前真实在线 DLL 总数。

它只表示“控制信号成功投递到多少个监听实例”。

## 4. Runtime 摘要结构

新增轻量摘要：

```cpp
struct AmsiIpcBroadcastSummary {
    std::string command;
    uint32_t reached = 0;
    uint32_t lastError = 0;
    uint32_t timeoutMs = 0;
};
```

`AmsiIpcRuntime` 内部保存最近一次：

- `lastReloadBroadcast`
- `lastUnloadBroadcast`
- `lastPauseBroadcast`
- `lastResumeBroadcast`

对外提供：

```cpp
AmsiIpcBroadcastSummary GetLastBroadcastSummary(const std::string& command) const;
AmsiIpcRuntimeStats GetStats() const;
```

`AmsiIpcRuntimeStats` 增加：

```cpp
uint32_t lastReloadReached;
uint32_t lastReloadLastError;
uint32_t lastPauseReached;
uint32_t lastPauseLastError;
uint32_t lastResumeReached;
uint32_t lastResumeLastError;
uint32_t lastUnloadReached;
uint32_t lastUnloadLastError;
```

## 5. 操作流程

### 5.1 Reload `0x01`

```text
UpdateRules(snapshot)
Broadcast(0x01)
记录 reload.reached / reload.lastError
```

### 5.2 Unload `0x02`

```text
Broadcast(0x02)
记录 unload.reached / unload.lastError
可选：后续按 reached 等待 drain-ack
```

### 5.3 Pause `0x03`

```text
Broadcast(0x03)
记录 pause.reached / pause.lastError
```

### 5.4 Resume `0x04`

```text
Broadcast(0x04)
记录 resume.reached / resume.lastError
```

## 6. 业务日志

`AmsiIpcRuntime` 每次广播后输出：

```text
Amsi reload broadcast reached=N lastError=0 timeoutMs=3000.
Amsi pause broadcast reached=N lastError=0 timeoutMs=1000.
Amsi resume broadcast reached=N lastError=0 timeoutMs=1000.
Amsi unload broadcast reached=N lastError=0 timeoutMs=1000.
```

`AmsiDetectTask` 在 StartCheck / UpgradeDownloadPackage / UnInit 关键路径额外输出业务语义日志，方便现场排障。

## 7. 已知限制

1. `reached=0` 可能表示没有 DLL 监听、DLL 尚未加载、权限不通、pipe 未创建或进程刚好退出。
2. 多个 listener 代表 config pipe 监听实例，不一定等于唯一进程数。
3. `reload / pause / resume` 当前没有完成 ACK。
4. `unload` 的 `drain-ack` 仍走 event pipe，本阶段不做强等待。
5. 后续如果需要精确命令完成状态，再单独设计 `CONTROL_ACK` 或 `broadcastId`，不要混入本阶段。

## 8. 当前业务流程约束（2026-05-28 修订）

结合当前 `AmsiDetectTask.cpp` 与 DLL Host liveness 语义，本阶段控制命令顺序按以下约束执行。

### 8.1 StartCheck 启动恢复顺序

当前代码历史上存在 `resume -> reload` 的实现，但后续应调整为：

```text
StartCheck()
  -> 读取并校验本地 AMSI 规则快照
  -> StartAmsiIpc(snapshot)
  -> RegisterAmsiProvider()
  -> Reload(0x01)
  -> ResumeDetection(0x04)
```

原因：

- Host/业务进程异常退出后，已加载 DLL 会进入 paused / host-lost 状态。
- DLL 侧 reload 成功只表示规则快照重新拉取成功，不等价于检测恢复。
- resume 必须发生在 reload 之后，避免 DLL 在旧规则或 snapshot 未就绪时恢复检测。
- 正常在线规则更新只需要 `UpdateRules(snapshot) -> Reload(0x01)`，不需要额外 resume。

### 8.2 StartCheck 广播结果处理

`Reload()` 和 `ResumeDetection()` 当前仍基于 `reached` 统计，不是强 ACK。

建议业务日志区分：

```text
Reload amsi rules broadcast reached=N.
Resume amsi detection broadcast reached=M.
```

其中：

- `reload.reached > 0` 表示至少有 DLL listener 收到 reload 控制字节。
- `resume.reached > 0` 表示至少有 DLL listener 收到 resume 控制字节。
- `lastError=2` 且 `reached > 0` 时，通常表示广播循环后续没有更多 listener，不应直接按整体失败处理。
- 如果 `reload.reached == 0`，`resume` 可以继续作为 best-effort 尝试，但不能宣称已完成恢复。

### 8.3 UnInit 当前阶段只 pause

本阶段 `AmsiDetectTask::UnInit()` 暂不补 `Unload(0x02)`，只保留：

```text
UnInit()
  -> UnregisterAmsiProvider()
  -> PauseDetection(0x03)
  -> StopAmsiIpcIfStarted()
```

约束：

- `PauseDetection()` 是当前退出路径的最小安全动作。
- `Unload(0x02)` / drain-ack 等待仍作为后续增强，不进入本轮实现。
- 因此当前 `UnInit` 不应因为没有 unload ack 而阻塞或失败。

### 8.4 规则快照字段当前阶段约束

当前业务阶段暂不考虑 `allRulesJson` 和 `hash`，不把它们作为启动、联调或验收的硬约束。

本阶段 `LoadRuleSnapshot()` 只要求保证：

```text
amsiRulesJson = 当前下发给 DLL 的规则 JSON
version       = version.conf / 编译产物版本
```

约束：

- `GET_RULES` 必须能返回 `amsiRulesJson`。
- `GET_ALL_RULES` 在当前阶段可以返回同一份 `amsiRulesJson`，不要求单独维护 `allRulesJson`。
- `RULE_LOAD_RESULT` 中的 hash 字段当前允许为空，不作为联调失败条件。
- 后续如果需要规则审计、hash 对齐、差异排障，再恢复 `allRulesJson / hash` 同源快照要求。
