# Phase 2 批次 1 测试计划

## 范围

本计划仅验证 Phase 2 首批已批准内容：

1. `EngineRuntime` 状态网关。
2. `ScanGuard` 和 `active_scan_count`。
3. `RuleSnapshot` 通过 `shared_ptr<const RuleSnapshot>` 发布。

本计划有意不验证 Lua/PCRE2 超时预算、异步事件队列、会话缓存或采样窗口。这些属于后续 Phase 2 批次。

## 测试入口点

主脚本：

```powershell
.\scripts\test_phase2_batch1.ps1
```

CMake 配置完成后快速本地重跑：

```powershell
.\scripts\test_phase2_batch1.ps1 -SkipConfigure -StressLoops 10
```

严格压力测试：

```powershell
.\scripts\test_phase2_batch1.ps1 -StressLoops 200
```

脚本默认使用 `src\rasp_mod_amsi\build-codex` 并验证：

- `engine_runtime_tests.exe` 构建成功。
- `rasp_mod_amsi.dll` 构建成功。
- `engine_runtime_tests.exe` 运行一次。
- `engine_runtime_tests.exe` 在压力循环中存活。
- 源码级禁止模式不存在。
- `git diff --check` 无空白错误。

## 构建测试

脚本覆盖的命令：

```powershell
cmake -S src\rasp_mod_amsi -B src\rasp_mod_amsi\build-codex -G "Visual Studio 17 2022" -A x64 -DFETCHCONTENT_UPDATES_DISCONNECTED=ON -DFETCHCONTENT_FULLY_DISCONNECTED=ON
cmake --build src\rasp_mod_amsi\build-codex --config Release --target engine_runtime_tests
cmake --build src\rasp_mod_amsi\build-codex --config Release --target rasp_mod_amsi
```

通过标准：

- 产出 `engine_runtime_tests.exe`。
- 产出 `rasp_mod_amsi.dll`。
- 无链接错误。
- 无新增生命周期或并发相关编译警告。

已知残留警告类别：

- `rasp_mod_amsi.h` 的历史源码编码警告可能在完整重建时出现。非 Phase 2 批次 1 引入，应作为独立清理处理。

## 运行时测试覆盖

当前 C++ 测试程序：

```text
src\rasp_mod_amsi\tests\engine_runtime_tests.cpp
```

验证：

- 新运行时启动状态为 `Uninitialized`。
- `EnsureInitialized()` 将运行时切换到 `Ready`。
- `TryEnterScan()` 仅在 ready 运行时成功。
- `ScanGuard` 进入时递增 `active_scan_count`。
- `ScanGuard` 销毁时递减 `active_scan_count`。
- `BeginShutdown()` 在有活跃扫描时有超时上限的排水等待。
- 关闭超时进入 `Inert`。
- `Inert` 拒绝新扫描。
- 并发扫描入口在工作线程退出后释放 `active_scan_count`。

手动命令：

```powershell
.\src\rasp_mod_amsi\build-codex\Release\engine_runtime_tests.exe
```

通过标准：

- 退出码为 `0`。
- 无 `FAIL:` 输出行。

## 静态架构检查

脚本拒绝以下回归：

- 源码中再次出现 `g_engine` 使用。
- 源码中再次出现 `g_unloadInProgress` 使用。
- `RuleSnapshot` 回退到 `std::atomic<RuleSnapshot*>`。
- 再次出现 `m_snapshot.exchange()` 或 `m_snapshot.load()` 裸指针风格。
- 手动删除旧快照。
- `amsi_provider.cpp` 添加 provider 级 `std::lock_guard` 或 `std::unique_lock`。
- 运行时代码中出现 `TerminateThread`。
- 关闭排水逻辑中 `wait_for` 缺失。
- 扫描路径中 `ScanGuard scan = runtime.TryEnterScan()` 缺失。

手动等效命令：

```powershell
rg -n "\bg_engine\b|\bg_unloadInProgress\b|atomic<RuleSnapshot|RuleSnapshot\*|m_snapshot\.exchange|m_snapshot\.load|delete\s+old|delete\s+snapshot" src\rasp_mod_amsi
```

通过标准：

- 生成构建目录外无禁止匹配。

## 验收矩阵

| 要求 | 验证 |
| --- | --- |
| 业务代码不直接读取 `g_engine` | 静态禁止模式检查 |
| `CreateInstance` 进入运行时 | 静态 provider 检查 |
| `Scan` 进入运行时 | 静态 provider 检查加测试程序 |
| `ScanGuard` 释放活跃计数 | 测试程序 |
| 关闭拒绝新扫描 | 测试程序 |
| 关闭排水有上限 | 测试程序加 `wait_for` 静态检查 |
| `RuleSnapshot` 不手动删除 | 静态禁止模式检查 |
| `Evaluate()` 持有本地共享快照 | 代码审查加共享指针模式检查 |
| DLL 仍可构建 | CMake 构建目标 |
| 运行时测试程序可重复运行 | 压力循环 |

## 缺口与后续测试

批次 1 不覆盖：

- 真实 COM/AMSI 宿主在 `powershell.exe` 中加载。
- 真实 `IAmsiStream` 扫描提取。
- 与活跃 sentry 的规则 reload 成功/失败。
- Lua 超时和正则限制行为。
- IPC 断连行为。
- 事件/日志队列行为。

批次 2 推荐后续：

- 添加 reload/shutdown 竞态测试程序。
- 添加显式 reload 失败保留旧快照测试。
- 添加 `reload_begin`、`reload_success`、`reload_failed` 和 `shutdown_drain_timeout` 遥测断言。