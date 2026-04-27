# Phase 2 第二批：Reload / Shutdown / Unload 仲裁与可观测性固化设计

## 1. 批次目标

本批目标是把 `Reload` 正式纳入 `EngineRuntime` 状态机，消除 `reload / scan / shutdown / unload` 并发下的状态错乱风险，并通过轻量 telemetry 让状态流转可审计。

核心目标：

- `OnReloadSignal()` 不再绕过 runtime。
- `ReloadGuard` 统一管理 reload 发布窗口。
- `Shutdown / Unload` 优先级高于 `Reloading`。
- `Reloading` 不阻塞 scan，scan 可继续使用旧 snapshot。
- reload 失败默认保留旧 snapshot，不进入 `Faulted`。
- `Faulted` 只用于 runtime / engine 不可信的严重错误。
- 所有关键拒绝、状态切换、失败原因都有 telemetry。

本批不做：

- Lua / PCRE2 超时熔断
- 事件异步队列
- session cache
- 样本窗口扫描
- 检测规则增强
- 复杂 telemetry 后端上报

## 2. 状态机设计

状态优先级：

```text
Stopping > Reloading
Inert > 所有业务动作
Faulted > 普通业务动作
Stopped 为终态
```

状态行为表：

| 状态 | Scan | Reload | Shutdown / Unload |
| --- | --- | --- | --- |
| `Uninitialized` | 可尝试初始化 | 拒绝 | 进入 `Inert` |
| `Initializing` | 拒绝 | 拒绝 | 进入 `Stopping` |
| `Ready` | 允许 | 允许 | 进入 `Stopping` |
| `Reloading` | 允许使用旧 snapshot | 拒绝重复 reload | shutdown 优先，进入 `Stopping` |
| `Stopping` | 拒绝 | 拒绝 | 继续 drain |
| `Inert` | 快速拒绝 / 降级 | 拒绝 | 可进入 `Stopped` |
| `Stopped` | 拒绝 | 拒绝 | 无动作 |
| `Faulted` | 拒绝 | 拒绝 | 可进入 `Inert` |

关键约束：

- `Reloading` 只表示短暂发布仲裁窗口，不表示整个规则构建过程。
- `ReloadGuard::Complete()` 只有当前状态仍是 `Reloading` 时才允许恢复 `Ready`。
- 如果状态已经变成 `Stopping / Inert / Stopped / Faulted`，`Complete()` 只能记录 telemetry，不能恢复 `Ready`。
- `ReloadGuard` 析构时如果未 `Complete()`，按 `reload_failed` 处理，但同样不能覆盖 shutdown / inert / faulted 状态。

## 3. ReloadGuard 设计

新增 `ReloadGuard`：

```cpp
class ReloadGuard {
public:
    ReloadGuard() = default;
    ReloadGuard(ReloadGuard&&) noexcept;
    ReloadGuard& operator=(ReloadGuard&&) noexcept;
    ~ReloadGuard();

    bool IsActive() const;
    void Complete(bool success, const char* detail = nullptr);

    ReloadGuard(const ReloadGuard&) = delete;
    ReloadGuard& operator=(const ReloadGuard&) = delete;
};
```

语义：

- `TryEnterReload()` 成功后返回 active guard。
- guard active 时 runtime 状态短暂进入 `Reloading`。
- `Complete(true)`：如果仍是 `Reloading`，切回 `Ready`，记录 `reload_success`。
- `Complete(false)`：如果仍是 `Reloading`，切回 `Ready`，记录 `reload_failed`。
- 析构未完成：等价 `Complete(false, "guard_destructor")`。
- 如果 shutdown 已经切走状态，`Complete()` 不改变状态，只记录 `reload_complete_ignored`。

## 4. Runtime API 设计

新增接口：

```cpp
bool CanAttemptReload() const;
ReloadGuard TryEnterReload(const char* reason);
void EmitTelemetry(const char* event, const char* detail = nullptr) const;
```

`CanAttemptReload()`：

- 只做快速状态判断。
- 不切状态。
- 不连接 sentry。
- 不解析 JSON。
- 不持锁执行复杂逻辑。
- 第一版仅允许 `Ready` 状态返回 true。

`TryEnterReload()`：

- 只在 `Ready` 下成功。
- 成功后 `Ready -> Reloading`。
- 失败时记录 `reload_rejected`。
- 不做 IPC、JSON parse、Lua、PCRE2。

`EmitTelemetry()`：

- 第一版只使用 `OutputDebugStringA`。
- 不写 pipe。
- 不等待 sentry。
- 不做复杂后端上报。
- 不在 runtime mutex 内执行阻塞操作。

## 5. Reload 流程设计

优先采用拆分模型：

```text
CanAttemptReload()
  -> BuildNextSnapshot()
  -> TryEnterReload()
  -> PublishSnapshot(next)
  -> ReloadGuard.Complete(true)
```

推荐 `OnReloadSignal()` 流程：

```cpp
void AmsiRuleEngine::OnReloadSignal() {
    auto& rt = GetAmsiEngineRuntime();

    if (!rt.CanAttemptReload()) {
        rt.EmitTelemetry("reload_rejected", "state_not_reloadable");
        return;
    }

    std::shared_ptr<const RuleSnapshot> next;
    bool buildOk = false;

    try {
        next = BuildNextSnapshot();
        buildOk = (next != nullptr);
    } catch (...) {
        buildOk = false;
    }

    if (!buildOk) {
        rt.EmitTelemetry("reload_failed", "build_snapshot_failed");
        return;
    }

    auto guard = rt.TryEnterReload("reload_signal");
    if (!guard.IsActive()) {
        rt.EmitTelemetry("reload_rejected", "shutdown_or_state_changed");
        return;
    }

    bool published = false;
    try {
        PublishSnapshot(next);
        published = true;
    } catch (...) {
        published = false;
    }

    guard.Complete(published, published ? "published" : "publish_failed");
}
```

`BuildNextSnapshot()`：

- 可以执行 sentry 连接、规则拉取、JSON parse、Lua precompile、PCRE2 precompile。
- 不持 runtime mutex。
- 不修改当前 `m_snapshot`。
- 构建失败不影响旧 snapshot。

`PublishSnapshot(next)`：

- 只执行 `atomic_store(&m_snapshot, next)`。
- 必须在 `ReloadGuard` active 后执行。
- 发布后 snapshot 不可变。

兜底策略：

- 如果本批拆分成本过高，可以临时保留 `ParseAndSwap()` 直接发布模式。
- 但必须在文档中标记为 transitional design debt。
- 技术债内容：snapshot 发布早于 runtime `Reloading` 仲裁窗口，状态机审计不够干净。
- 建议第三批前修掉。

## 6. Snapshot 设计

当前第一批已改成：

```cpp
std::shared_ptr<const RuleSnapshot> m_snapshot;
```

第二批建议进一步拆分：

```cpp
std::shared_ptr<const RuleSnapshot> BuildNextSnapshot(
    const std::string& json,
    const std::string& libSource);

void PublishSnapshot(std::shared_ptr<const RuleSnapshot> next);
```

约束：

- `BuildNextSnapshot()` 不写 `m_snapshot`。
- `PublishSnapshot()` 是唯一发布入口。
- `Evaluate()` 开头继续 `atomic_load(&m_snapshot)`。
- reload 失败不清空旧 snapshot。
- 不允许 `delete old snapshot`。
- 不允许回退到 `RuleSnapshot*`。

## 7. Shutdown / Unload 仲裁

`BeginShutdown()` 必须覆盖 `Reloading`。

行为：

- 当前 `Ready`：切 `Stopping`，拒绝新 scan / reload。
- 当前 `Reloading`：直接切 `Stopping`，shutdown 优先。
- 当前 `Stopping`：继续 drain。
- 当前 `Inert / Stopped`：不做复杂动作。
- 当前 `Faulted`：允许进入 `Inert`。

关键约束：

- `BeginShutdown()` 不无限等待。
- drain 超时进入 `Inert`。
- `ReloadGuard::Complete()` 后续不得把状态恢复成 `Ready`。
- unload signal 路径继续使用短等待，例如 `200ms`。
- 普通 shutdown 后续可扩展为 `2s~5s`，本批不扩大。

## 8. Faulted 语义

普通 reload 失败不进入 `Faulted`。

普通失败包括：

- sentry 暂时连接失败
- 规则拉取失败
- JSON 解析失败
- 单条规则预编译失败
- 规则为空
- reload 期间状态被 shutdown 抢占

处理：

```text
reload_failed -> Ready
旧 snapshot 继续生效
记录 telemetry
```

进入 `Faulted` 的条件：

- engine 指针异常
- runtime 内部不变量破坏
- active scan count 下溢
- 初始化后核心对象丢失
- snapshot 发布机制损坏
- 无法保证旧 snapshot 安全

`Faulted` 行为：

- 拒绝 scan。
- 拒绝 reload。
- 不自动重试。
- 可被 shutdown / unload 带入 `Inert`。

## 9. Telemetry 事件

本批必须固化以下事件：

```text
state_transition
scan_enter_rejected
reload_rejected
reload_begin
reload_success
reload_failed
reload_complete_ignored
shutdown_begin
shutdown_drain_timeout
enter_inert
faulted
```

字段建议：

```text
event
old_state
new_state
reason
detail
active_scan_count
thread_id
```

第一版输出示例：

```text
[RaspAmsi] telemetry event=reload_begin state=Reloading reason=reload_signal active=2 tid=1234
```

限制：

- 不做 JSON。
- 不写 pipe。
- 不等待 sentry。
- 不在 runtime mutex 内阻塞。

## 10. 测试方案

扩展 `engine_runtime_tests.cpp`。

必须覆盖：

- `TryEnterReload()` 只有 `Ready` 成功。
- `Reloading` 拒绝重复 reload。
- `Reloading` 允许 scan 进入。
- `Stopping / Inert / Faulted / Stopped` 拒绝 reload。
- `ReloadGuard::Complete(true)` 正常恢复 `Ready`。
- `ReloadGuard` 未 `Complete()` 析构，按失败恢复 `Ready`。
- reload 中 shutdown，shutdown 优先进入 `Stopping / Inert`。
- shutdown 后 `ReloadGuard::Complete(true)` 不得恢复 `Ready`。
- reload build 成功但 publish 前 shutdown，`TryEnterReload()` 失败。
- `Faulted` 拒绝 scan / reload。
- active scan count 不下溢。

新增脚本：

```text
scripts/test_phase2_batch2.ps1
```

脚本必须执行：

- 构建 `engine_runtime_tests`
- 构建 `rasp_mod_amsi.dll`
- 运行 harness
- 多轮 stress loop
- 静态 grep 检查

静态检查项：

- `OnReloadSignal` 必须走 `CanAttemptReload` / `TryEnterReload`。
- reload 路径不得直接写 runtime state。
- reload 路径不得持 runtime mutex 执行 IPC / JSON parse / Lua / PCRE2。
- 无 `g_engine` 回归。
- 无 `g_unloadInProgress` 回归。
- 无裸 `RuleSnapshot*` 回归。
- 无手动 delete snapshot 回归。
- 不出现 `TerminateThread`。
- 不出现事件队列、Lua / PCRE2 timeout 等超范围改动。

## 11. 修改文件

计划修改：

```text
docs/phase2_batch2_reload_shutdown_design.md
src/rasp_mod_amsi/include/engine_runtime.h
src/rasp_mod_amsi/src/engine_runtime.cpp
src/rasp_mod_amsi/src/amsi_rule_engine.cpp
src/rasp_mod_amsi/tests/engine_runtime_tests.cpp
scripts/test_phase2_batch2.ps1
```

如果拆 `BuildNextSnapshot / PublishSnapshot`，还会修改：

```text
src/rasp_mod_amsi/include/amsi_rule_engine.h
```

## 12. 实施顺序

建议严格按以下顺序：

1. 写 `docs/phase2_batch2_reload_shutdown_design.md`。
2. 扩展 `engine_runtime_tests.cpp`，先定义预期行为。
3. 实现 `ReloadGuard`。
4. 实现 `CanAttemptReload()`。
5. 实现 `TryEnterReload()`。
6. 实现轻量 `EmitTelemetry()`。
7. 修改 `TryEnterScan()`，允许 `Reloading`。
8. 修改 `BeginShutdown()`，覆盖 `Reloading`。
9. 优先拆 `BuildNextSnapshot()` / `PublishSnapshot()`。
10. 接入 `OnReloadSignal()` runtime 仲裁。
11. 新增 `scripts/test_phase2_batch2.ps1`。
12. 构建、测试、stress loop。
13. 独立 commit。
14. 独立 review。
15. 推送远程 `codex`。

## 13. 最终验收标准

构建验收：

- `rasp_mod_amsi.dll` 构建通过。
- `engine_runtime_tests.exe` 构建通过。
- `test_phase2_batch2.ps1` 通过。

状态机验收：

- reload 只能在允许态进入。
- reload 不覆盖 shutdown。
- shutdown 后 scan / reload 被拒绝。
- `ReloadGuard::Complete()` 不恢复错误状态。
- `Faulted` 拒绝 scan / reload。
- `Reloading` 允许 scan 使用旧 snapshot。

并发验收：

- scan + reload 压力循环不崩。
- reload + shutdown 压力循环不恢复错状态。
- reload build 成功但 publish 前 shutdown 时不发布、不恢复 `Ready`。
- reload 失败旧 snapshot 继续有效。

代码验收：

- 无 `g_engine / g_unloadInProgress` 回归。
- 无裸 `RuleSnapshot*` / 手动 delete 回归。
- runtime mutex 不包住 IPC / JSON parse / Lua / PCRE2。
- 不引入 Lua / PCRE2 熔断、事件队列、session cache 等超范围内容。
