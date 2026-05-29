# AMSI Config Control State-Pull Migration Design

## 1. 背景

当前旧控制链路是：

```text
每个 DLL 实例创建 \\.\pipe\amsi_detect_config
Host 连接该 pipe 并写入 1 字节控制信号
```

这会带来几个现实问题：

- `resume` 执行很快，同一个 DLL 可能反复重建 pipe，导致 `resume reached=256` 这类重复计数。
- `reached` 只是 `WriteFile` 成功次数，不等于唯一 DLL 实例数。
- `explorer.exe`、`winmgmt` 等常驻进程可能长期消费控制信号。
- 不同权限进程创建同名 pipe 时容易出现 ACL / GLE=5 等冲突。
- Host 异常退出后，已加载 DLL 不能继续使用旧规则拦截，需要统一进入 bypass。

此前考虑过 Host 维护 v2 session 表，由 Host 主动逐个 session 下发 `reload/pause/resume/unload`。当前阶段调整为更简单的方案：

```text
Host 不维护 DLL session 表
Host 只暴露一个统一目标状态
DLL 主动拉取 Host state，并按 state 自行收敛
```

## 2. 目标模型

新的核心模型：

```text
Host 不在线  -> DLL bypass
Host 在线    -> DLL 主动拉取统一 state
state=running -> DLL 判断规则版本，加载规则并进入 running
state=unload  -> DLL 进入 inert/unloaded，直到进程重启或 DLL 重新加载
```

不再把 `pause` / `resume` 作为核心控制状态。

长期控制语义收敛为：

```text
running = Host 在线且允许检测
unload  = DLL 升级维护窗口，旧 DLL 需要进入 inert
```

## 3. 统一 State 响应

Host 提供一个统一状态响应。可以新增 `GET_STATE`，也可以在当前阶段复用 `GET_RULES` 返回 envelope。

推荐语义名称：

```text
GET_STATE
```

统一结构：

```json
{
  "state": "running",
  "stateVersion": "2026063002",
  "ruleVersion": "2026063002",
  "rules": {}
}
```

DLL 升级窗口也使用同一个结构：

```json
{
  "state": "unload",
  "stateVersion": "upgrade-2026063002",
  "ruleVersion": "2026063001",
  "rules": {}
}
```

字段说明：

| 字段 | 含义 |
| --- | --- |
| `state` | Host 目标状态，只允许 `running` / `unload` |
| `stateVersion` | Host 状态版本。`running <-> unload` 切换时变化 |
| `ruleVersion` | 当前规则版本。`state=running` 时用于判断是否需要更新规则 |
| `rules` | 当前规则内容。`state=running` 时解析；`state=unload` 时可为空对象并被 DLL 忽略 |

当前阶段不强制 `allRulesJson` 和 `hash`。

## 4. DLL 本地状态

DLL 本地维护最小状态：

```text
hostOnline
localState          // running / bypass / inert
localStateVersion
localRuleVersion
ruleSnapshotReady
inert
```

`inert` 是硬状态：

```text
一旦 DLL 因 state=unload 进入 inert，不允许因为后续 state=running 自动恢复。
只能等进程重启或 DLL 重新加载。
```

## 5. DLL 决策逻辑

DLL 每次拉取 Host state 后，按固定优先级处理：

```text
1. Host 不在线
   -> bypass

2. Host 在线，state=unload
   -> inert

3. Host 在线，state=running
   -> 判断 ruleVersion
```

伪代码：

```cpp
if (inert) {
    return NoMatch;
}

HostState state;
if (!PullStateFromHost(state)) {
    EnterBypass("host offline");
    return NoMatch;
}

if (state.state == "unload") {
    EnterInert("host requested unload");
    return NoMatch;
}

if (state.state == "running") {
    if (state.ruleVersion == localRuleVersion && ruleSnapshotReady) {
        EnterRunning("rules already current");
        return Detect();
    }

    EnterBypass("rules need reload");

    if (LoadRules(state.rules)) {
        localRuleVersion = state.ruleVersion;
        ruleSnapshotReady = true;
        EnterRunning("rules loaded");
        return Detect();
    }

    ruleSnapshotReady = false;
    EnterBypass("rules load failed");
    return NoMatch;
}
```

### 5.1 Host 不在线

Host 不在线时统一处理：

```text
hostOnline=false
localState=bypass
Scan 返回 NoMatch
不继续使用旧规则拦截
```

### 5.2 state=running

规则版本一致：

```text
如果 DLL 已经 running：
  继续 running

如果 DLL 之前是 bypass：
  只要 ruleSnapshotReady=true，恢复 running
```

规则版本不一致：

```text
先进入 bypass
加载新规则
成功 -> running
失败 -> bypass
```

### 5.3 state=unload

`unload` 只用于 DLL 文件升级，不用于普通策略关闭。

DLL 拉到 `state=unload` 后：

```text
inert=true
localState=inert
停止检测
Scan 永远返回 NoMatch
不再解析 rules
不再判断 ruleVersion
不因后续 state=running 自动恢复
```

## 6. Host 行为

### 6.1 正常运行

Host 在线且检测开启时：

```json
{
  "state": "running",
  "stateVersion": "2026063002",
  "ruleVersion": "2026063002",
  "rules": {}
}
```

Host 不需要知道哪些 DLL 在线，也不需要维护 session 表。

### 6.2 规则更新

规则更新只改变：

```text
ruleVersion
rules
stateVersion 可选变化
```

DLL 主动拉取到新 `ruleVersion` 后自行加载新规则。

旧 `reload` 命令可以保留为加速提示，但最终是否 reload 以 `ruleVersion` 是否变化为准。

### 6.3 策略关闭

当前约束：

```text
策略关闭时 Host 不走 AMSI init，不创建通信通道。
```

因此：

```text
新进程不会加载 DLL 或不会进入 AMSI 检测链路。
已加载 DLL 发现 Host 不在线 -> bypass。
```

当前阶段不需要单独 `pause` 状态。

如果未来出现“Host 在线但策略关闭仍保留 IPC”的模式，需要新增 `state=disabled` 或 `policyEnabled=false`，不在本阶段范围内。

### 6.4 DLL 升级

DLL 升级时使用临时 `unload` 维护窗口。

Host 流程：

```text
1. SetState(unload)
2. 在固定时间窗内持续暴露 state=unload
3. 可选：同时循环广播旧 0x02 unload，兼容旧 DLL
4. 时间窗结束后替换 hss_amsi.dll
5. 更新规则/版本文件
6. SetState(running)
```

推荐初始参数：

```text
unloadWindowMs = 9000
cycleCount = 3
cycleIntervalMs = 3000
```

示例：

```text
T0:    state=unload
T0+3s: state=unload
T0+6s: state=unload
T0+9s: 替换 DLL，更新版本
T0+9s: state=running
```

约束：

- `state=unload` 是升级维护态，不能长期停留。
- `state=running` 恢复后，只用于新 DLL 或未进入 inert 的实例。
- 已经进入 inert 的旧 DLL 不允许恢复。

## 7. 与旧控制命令的关系

当前旧信号可以保留为兼容手段：

| 旧信号 | 当前定位 |
| --- | --- |
| `0x01 reload` | 可选加速提示，最终以 `ruleVersion` 判断为准 |
| `0x02 unload` | DLL 升级窗口内的兼容广播，等价于 `state=unload` |
| `0x03 pause` | 当前方案不作为核心状态 |
| `0x04 resume` | 当前方案不作为核心状态 |

长期目标：

```text
Host state + DLL 主动拉取
替代 reload/pause/resume 这类瞬时命令
```

## 8. 与 Host Liveness 的关系

DLL 判断 Host 在线的方式可以继续复用现有 rule pipe / state pipe 探测。

状态优先级：

```text
inert > Host offline > state=unload > state=running
```

解释：

- `inert` 最高优先级，不能恢复。
- Host offline 时一律 bypass。
- Host online 且 `state=unload` 时进入 inert。
- Host online 且 `state=running` 时才检查规则并恢复检测。

## 9. Observability 边界

本方案不依赖 Host session 表，因此不能通过 config session 得到精确 DLL 在线数。

DLL 在线视图仍应来自：

- `DLL_LOADED`
- `RULE_LOAD_RESULT`
- `DLL_HEARTBEAT`
- `DLL_UNLOADED`
- `lastSeen / staleThreshold`

推荐指标仍为：

```text
onlineDllCount
staleDllCount
historicalLoadedDllCount
```

不要把 `GET_STATE` 请求次数或 rule pipe 连接次数当作 DLL 在线数量。

## 10. 安全要求

虽然不维护 session 表，Host 仍需要保护 state/rule 响应入口：

- 限制请求命令类型。
- 限制响应大小。
- JSON 必须 UTF-8。
- `state` 只允许 `running` / `unload`。
- `rules` 只在 `state=running` 时被 DLL 解析。
- 规则内容加载失败时 DLL 必须 bypass。
- Host 不在线时 DLL 不允许继续旧规则拦截。

## 11. 迁移阶段

### Phase 1: Host 输出统一 state

Host:

- 增加统一 state 结构。
- `state=running` 时返回规则。
- `state=unload` 时返回同一 envelope，但 DLL 忽略规则字段。

DLL:

- 先只解析 `state=running`。
- 保持旧 `reload/resume/pause/unload` 兼容。

### Phase 2: DLL 主动按 state 收敛

DLL:

- Host offline -> bypass。
- `state=running` -> 按 `ruleVersion` 加载规则并 running。
- `state=unload` -> inert。

Host:

- 常规规则更新只更新 `ruleVersion/rules`。
- 不再依赖 `resume` 恢复检测。

### Phase 3: DLL 升级窗口接入 unload state

Host:

- 升级前设置 `state=unload`。
- 在固定窗口内保持 unload。
- 可选循环广播旧 `0x02 unload`。
- 替换 DLL 后设置 `state=running`。

DLL:

- 拉到 unload 后进入 inert。
- 不因后续 running 自动恢复。

### Phase 4: 弱化旧控制命令

- `reload` 仅作为加速提示。
- `pause/resume` 不再作为核心状态。
- `unload` 只作为 DLL 升级兼容广播。

## 12. 测试计划

1. Host 正常在线，`state=running`，规则版本一致：
   - DLL 保持 running。

2. Host 异常退出：
   - DLL 进入 bypass。
   - Scan 返回 NoMatch。

3. Host 恢复，`state=running`，规则版本一致：
   - DLL 从 bypass 恢复 running。

4. Host 恢复，`state=running`，规则版本变化：
   - DLL 加载新规则。
   - 成功后 running。
   - 失败则 bypass。

5. 规则加载失败：
   - DLL 不进入 running。
   - 上报 `RULE_LOAD_RESULT success=false`。

6. DLL 升级：
   - Host 设置 `state=unload`。
   - DLL 拉到 unload 后进入 inert。
   - Host 恢复 `state=running` 后，旧 DLL 不恢复。
   - 新进程加载新 DLL 后按 running 拉规则并检测。

7. 旧命令兼容：
   - `0x02 unload` 在升级窗口仍可让旧 DLL inert。
   - `0x01 reload` 只作为提示，不绕过 `ruleVersion` 判断。

## 13. 已知限制

- Host 不维护 session 表，因此无法按实例精确下发命令。
- 无法证明所有旧 DLL 都收到 `unload`。
- 常驻进程中未拉到 `state=unload` 的旧 DLL 可能继续存在。
- 精确实例控制仍需要未来 v2 session 模型或进程级治理能力。
- 如果未来要求 Host 在线但策略关闭，需要新增 `disabled` 状态或 `policyEnabled=false`。

## 14. 推荐结论

当前阶段采用更简单的 state-pull 方案：

```text
Host 不在线，DLL bypass；
Host 在线且 state=running，DLL 根据 ruleVersion 加载规则并 running；
Host state=unload，只用于 DLL 升级，DLL 进入 inert 后不再恢复。
```

该方案避免 Host 维护复杂 session 表，降低迁移成本，同时解决 Host 异常退出后 DLL 继续旧规则拦截的问题。
