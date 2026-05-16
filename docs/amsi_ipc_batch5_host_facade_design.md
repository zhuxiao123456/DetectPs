# Batch 5 Host Facade 设计

## 1. 当前阶段

当前 IPC Host 抽离已经完成四条核心通道：

- Batch 1：`AmsiConfigBroadcaster`
- Batch 2：`AmsiRuleChannel`
- Batch 3：`AmsiEventChannel`
- Batch 4：`AmsiControlStatusChannel`

四条通道已经从 `rasp_sentry_native` 的具体业务类中拆出 transport seam，但 `rasp_sentry.exe` 的启动、停止、依赖组装仍分散在 `main.cpp`、`RuleServer`、`EventCollector`、`ControlStatusCollector`、`ConfigWatcher` 和 `AmsiStagingWatcher` 中。

Batch 5 的目标不是继续拆 wire 协议，而是定义 HostGuard 迁移时可以调用的稳定 facade，避免 HostGuard 直接依赖各个 collector/server 的内部启动细节。

## 2. 目标

本批目标：

- 设计 `AmsiIpcHost` facade。
- 定义 HostGuard 未来可复用的启动/停止入口。
- 明确四条通道的依赖注入边界。
- 明确 Start / Stop 顺序。
- 明确当前 `rasp_sentry.exe` 与未来 HostGuard 的职责差异。

第一阶段建议 design-only，不改生产逻辑。

## 3. 非目标

Batch 5 不做：

- 不接 HostGuard / EDR SDK。
- 不删除 `rasp_sentry.exe`。
- 不改 pipe name。
- 不改 JSON schema。
- 不改 reload / unload 语义。
- 不合并 event 和 control status 通道。
- 不改 DLL 侧 IPC client。
- 不改变 `RuleServer` / `EventCollector` / `ControlStatusCollector` 的业务语义。
- 不移动目录和文件物理归属。

## 4. Facade 目标形态

建议未来新增：

```cpp
namespace amsi_ipc {

struct AmsiIpcHostConfig {
    std::string logDir;
    std::string rulesPath;
    std::string stagingDir;
};

class AmsiIpcHost {
public:
    explicit AmsiIpcHost(AmsiIpcHostConfig config);
    ~AmsiIpcHost();

    bool Start();
    void Stop();

    AmsiIpcHost(const AmsiIpcHost&) = delete;
    AmsiIpcHost& operator=(const AmsiIpcHost&) = delete;
};

} // namespace amsi_ipc
```

说明：

- `AmsiIpcHost` 是 host-facing facade。
- `AmsiIpcHost` 不定义新 wire 协议。
- `AmsiIpcHost` 不解析规则 JSON。
- `AmsiIpcHost` 不理解 detection event schema。
- `AmsiIpcHost` 只组装现有 provider / sink / broadcaster / watcher。
- 当前 `AmsiIpcHostConfig` 只覆盖 demo `rasp_sentry.exe` 所需路径型参数。
- HostGuard 化时，`AmsiIpcHost` 不应只依赖路径配置硬编码创建全部内部对象；规则源、事件 sink、诊断日志 sink、staging/lifecycle 行为应允许通过 adapter 或构造参数注入。

## 5. 组件归属

| 组件 | 当前职责 | Batch 5 未来归属 | HostGuard 是否直接依赖 |
|---|---|---|---|
| `RuleServer` | 规则响应、规则缓存、规则组装 | `AmsiIpcHost` 内部依赖 | 否 |
| `EventCollector` | events JSONL 落盘、drain-ack 提取 | `AmsiIpcHost` 内部依赖 | 否 |
| `ControlStatusCollector` | RULE_LOAD_RESULT JSONL 落盘 | `AmsiIpcHost` 内部依赖 | 否 |
| `ConfigWatcher` | 监听规则文件变化并广播 reload | demo 控制面依赖 | HostGuard 化后替换 |
| `AmsiStagingWatcher` | staging DLL replace / unload drain | demo lifecycle 依赖 | HostGuard 化后评审 |
| `AmsiConfigBroadcaster` | reload / unload 广播 transport | facade 内部能力 | 否 |
| `AmsiRuleChannel` | rules pipe transport | facade 内部能力 | 否 |
| `AmsiEventChannel` | events pipe transport | facade 内部能力 | 否 |
| `AmsiControlStatusChannel` | control status pipe transport | facade 内部能力 | 否 |

`ConfigWatcher` 和 `AmsiStagingWatcher` 是 demo-only dependency。Batch 5a 可以继续由 facade 组装它们以保持 `rasp_sentry.exe` 行为，但 HostGuard 化时必须变为可选依赖或外部注入，不能作为 facade 固定内置成员。

## 6. Start 顺序建议

未来 HostGuard 化后 `AmsiIpcHost::Start()` 建议顺序：

1. 初始化规则 provider / `RuleServer`。
2. 启动 rules channel。
3. 启动 events channel。
4. 启动 control status channel。
5. 初始化 config broadcaster。
6. 启动 demo `ConfigWatcher`。
7. 启动 demo `AmsiStagingWatcher`。

理由：

- 规则服务优先启动，避免 DLL 初始化时拉规则失败。
- events 和 control status 先于 watcher 启动，避免 reload / load result 事件无接收端。
- watcher 最后启动，避免依赖通道未就绪时触发广播。

Batch 5a demo 实现约束：

- 为降低行为变化，`rasp_sentry.exe` 第一版 facade 可保持当前 main 的既有启动顺序：`EventCollector` -> `ControlStatusCollector` -> `RuleServer` -> `ConfigWatcher` -> `AmsiStagingWatcher`。
- 上述顺序只代表 demo 兼容实现，不代表 HostGuard 化后的最终推荐顺序。

失败回滚语义：

- `Start()` 如果中途失败，必须按已启动组件的逆序执行 `Stop()` 回滚。
- 回滚完成后返回 `false`。
- 不得留下半启动的 rule / event / control status / config watcher 状态。

## 7. Stop 顺序建议

未来 `AmsiIpcHost::Stop()` 建议反向停止：

1. 停止 demo `AmsiStagingWatcher`。
2. 停止 demo `ConfigWatcher`。
3. 停止 control status channel。
4. 停止 events channel。
5. 停止 rules channel。
6. 释放 rule provider / sink / collector。

约束：

- Stop 必须幂等。
- Stop 不得无限等待 DLL。
- Stop 不新增同步远程调用。
- Stop 不改变现有 collector/server 的超时语义。

## 8. HostGuard 迁移边界

未来 HostGuard 只应依赖：

```cpp
AmsiIpcHostConfig
AmsiIpcHost
```

HostGuard 不应直接依赖：

- `RuleServer`
- `EventCollector`
- `ControlStatusCollector`
- `NamedPipeServerPool`
- `AmsiRuleChannel`
- `AmsiEventChannel`
- `AmsiControlStatusChannel`
- `AmsiConfigBroadcaster`

如果 HostGuard 需要替换规则源、事件 sink 或日志 sink，应通过 facade 构造参数或更高层 adapter 注入，不直接改 IPC channel。

## 9. Batch 5a seam-only 实现边界

如果进入实现，第一批只允许：

- 新增 `src/rasp_sentry_native/include/amsi_ipc_host.h`
- 新增 `src/rasp_sentry_native/src/amsi_ipc_host.cpp`
- 新增 `AmsiIpcHostConfig`
- 新增 `AmsiIpcHost::Start()` / `Stop()` seam
- 可新增 fake 单测验证 Start/Stop 顺序

禁止：

- 不改 pipe name。
- 不改 collector/server 业务逻辑。
- 不接 HostGuard SDK。
- 不删除 `rasp_sentry.exe`。
- 不移动现有类。
- 不改变 JSONL 落盘路径。
- 不改变 reload / unload 行为。

路径说明：

- 当前 Batch 5a 的 `AmsiIpcHost` 是 demo host facade，负责组装 `rasp_sentry_native` 中的具体 `RuleServer` / `EventCollector` / `ControlStatusCollector` / watcher 对象。
- 因此第一版放在 `src/rasp_sentry_native`，避免让纯 transport 层 `src/amsi_ipc_host` 反向依赖 demo 业务类。
- HostGuard 化时可再将更窄的 host-facing interface 抽到平台 adapter 层。

## 10. 测试建议

Design-only 阶段不需要新增测试。

如果进入 Batch 5a seam-only，实现前建议先补 fake 测试：

- Start 顺序符合设计。
- Stop 顺序反向。
- Start 失败时能返回 false。
- Stop 可重复调用。
- 析构时会 Stop。

生产回归仍需运行：

```powershell
cmake --build src\rasp_sentry_native\build-codex --config Release --target amsi_config_broadcaster_tests
cmake --build src\rasp_sentry_native\build-codex --config Release --target amsi_rule_channel_tests
cmake --build src\rasp_sentry_native\build-codex --config Release --target amsi_event_channel_tests
cmake --build src\rasp_sentry_native\build-codex --config Release --target amsi_control_status_channel_tests
cmake --build src\rasp_sentry_native\build-codex --config Release --target rasp_sentry
git diff --check
```

## 11. 风险

| 风险 | 说明 | 缓解 |
|---|---|---|
| facade 变成上帝类 | 如果承载规则解析、事件处理、reload 语义，会重新耦合 | facade 只组装生命周期，不处理业务 |
| HostGuard 直接依赖内部类 | 迁移后仍会被 legacy 结构绑住 | 只暴露 `AmsiIpcHost` |
| Start/Stop 顺序改变行为 | 通道启动顺序影响 DLL 初始化和事件接收 | 写顺序测试 |
| 提前接 SDK | 会把本批从 seam 变成平台迁移 | Batch 5a 禁止接 HostGuard SDK |

## 12. 验收标准

Design-only 验收：

- 本文档存在。
- 明确 facade 职责。
- 明确 Start / Stop 顺序。
- 明确 HostGuard 不直接依赖内部类。
- 明确禁止项。
- 当前生产代码无变更。

实现批次验收：

- `AmsiIpcHost` 只封装生命周期。
- 四通道 wire 行为不变。
- 所有 IPC tests 通过。
- `rasp_sentry.exe` Release build 通过。
- 测试机规则拉取、事件落盘、控制状态落盘、reload 广播均不回退。
