# HostGuard Demo 独立联调程序方案

## 1. 目标

当前 IPC 已从 `rasp_sentry.exe` 内部逻辑逐步拆成可迁移的 HostGuard façade。未来目标是：

- HostGuard 只依赖：
  - `AmsiIpcHost`
  - `AmsiIpcHostConfig`
  - `AmsiIpcHostAdapters`
  - `IAmsiRuleProvider`
  - `IAmsiEventSink`
  - `IAmsiControlStatusSink`
- HostGuard 不直接依赖 demo 内部类：
  - `RuleServer`
  - `DemoFileRuleProvider`
  - `EventCollector`
  - `ControlStatusCollector`
  - `ConfigWatcher`
  - `AmsiStagingWatcher`

当前还没有真正独立的 `hostguard.exe` demo target。因此建议新增一个**最小联调壳程序**：

- 名称建议：`hostguard_demo.exe`
- 目标：验证不用 `rasp_sentry.exe`，只依赖 `AmsiIpcHost + ruleProvider + eventSink + controlStatusSink`，就能完整跑通：
  - DLL 拉规则
  - 规则 reload
  - 事件上报
  - 控制状态上报
  - unload 广播

---

## 2. 设计原则

### 2.1 总体原则

`hostguard_demo.exe` 不是正式 HostGuard，也不是为了替代当前生产实现，而是一个**独立联调程序**，验证 HostGuard 接入路径是否真实可用。

### 2.2 核心约束

允许：

- 复用 `AmsiIpcHost`
- 复用 `AmsiIpcHostConfig::ForHostGuard()`
- 复用 `AmsiIpcHostAdapters`
- 复用三类注入接口
- 使用文件规则 provider
- 使用 JSONL sink
- 提供简单控制台命令

禁止：

- 不接 HostGuard SDK
- 不修改 DLL
- 不修改 pipe 协议
- 不依赖 `rasp_sentry.exe`
- 不依赖 demo watcher
- 不直接 include / new 以下类：
  - `RuleServer`
  - `DemoFileRuleProvider`
  - `EventCollector`
  - `ControlStatusCollector`
  - `ConfigWatcher`
  - `AmsiStagingWatcher`

---

## 3. 推荐目录结构

建议新建**独立目录**，与现有 `rasp_sentry_native` 解耦：

```text
/tools/hostguard_demo/
  CMakeLists.txt
  README.md
  /src/
    main.cpp
    hostguard_demo_app.h
    hostguard_demo_app.cpp
    hostguard_file_rule_provider.h
    hostguard_file_rule_provider.cpp
    hostguard_jsonl_event_sink.h
    hostguard_jsonl_event_sink.cpp
    hostguard_jsonl_control_status_sink.h
    hostguard_jsonl_control_status_sink.cpp
    hostguard_command_loop.h
    hostguard_command_loop.cpp
    hostguard_paths.h
    hostguard_paths.cpp
  /config/
    rasp_rules.json
  /tests/
    hostguard_demo_smoke_tests.cpp
```

这样做的好处：

- 单独编译
- 单独 build 目录
- 不污染当前 `rasp_sentry_native` target
- 后续删除、迁移、替换都更容易

---

## 4. 编译方式

建议提供独立 `CMakeLists.txt`，单独生成 demo 可执行文件。

### 4.1 构建命令示例

```powershell
cmake -S tools/hostguard_demo -B build-hostguard-demo -G "Visual Studio 17 2022" -A x64
cmake --build build-hostguard-demo --config Release
```

### 4.2 独立编译要求

- 尽量只链接 `amsi_ipc_host` 相关公共接口/实现
- 不把 `hostguard_demo` target 塞进 `rasp_sentry_native/CMakeLists.txt`
- 不依赖当前 demo 的 main / watcher / collector / server

---

## 5. 核心组件设计

### 5.1 `HostGuardFileRuleProvider`

职责：

- 从指定文件读取规则，例如：`config/rasp_rules.json`
- 缓存完整规则 JSON 和 AMSI 过滤规则 JSON
- 实现 `IAmsiRuleProvider`
- 支持 `InvalidateRuleCache()`

建议接口：

```cpp
class HostGuardFileRuleProvider final : public amsi_ipc::IAmsiRuleProvider {
public:
    explicit HostGuardFileRuleProvider(std::string rulesPath);

    bool BuildRulesResponse(const std::string& command,
                            amsi_ipc::AmsiRuleResponse& out,
                            std::string& error) override;

    void InvalidateRuleCache() override;

private:
    std::string BuildAllRulesJson();
    std::string BuildAmsiRulesJson();

    std::string rulesPath_;
    std::shared_mutex lock_;
    std::string cachedAllRules_;
    std::string cachedAmsiRules_;
};
```

语义要求：

- `GET_RULES`：返回 AMSI DLL 可加载规则
- `GET_ALL_RULES`：返回完整 assembled JSON
- `InvalidateRuleCache()`：只清缓存，不要求同步重建
- 不要在 `BuildRulesResponse()` 内做远程请求
- 不要长时间持有锁

### 5.2 `HostGuardJsonlEventSink`

职责：

- 接收 `amsi_detect_events` 的原始 payload
- 原样写入 JSONL 文件

文件建议：

```text
C:\RaspSentry\rasp_logs\rasp-events-YYYY-MM-DD.jsonl
```

建议行为：

- 原样写入，不改 schema
- 一行一个 payload
- 可选打印简要控制台日志

### 5.3 `HostGuardJsonlControlStatusSink`

职责：

- 接收 `amsi_detect_control_status` 的原始 payload
- 原样写入 JSONL 文件

文件建议：

```text
C:\RaspSentry\rasp_logs\rasp-control-status-YYYY-MM-DD.jsonl
```

建议行为：

- 原样写入
- 不在第一版中做复杂状态机

### 5.4 `HostGuardDemoApp`

职责：

- 统一持有 provider、event sink、status sink、`AmsiIpcHost`
- 封装：
  - `Start()`
  - `Stop()`
  - `Reload()`
  - `Unload()`
  - `PrintStatus()`

---

## 6. HostGuard 模式配置

启动时建议使用：

```cpp
auto config = amsi_ipc::AmsiIpcHostConfig::ForHostGuard();
```

### 6.1 严格模式要求

`ForHostGuard()` 应满足：

- `enableDemoConfigWatcher = false`
- `enableDemoStagingWatcher = false`
- `strictHostGuardMode = true`
- 缺少 `ruleProvider / eventSink / controlStatusSink` 任一项时，`Start()` 返回 `false`
- 不允许静默 fallback 到 demo 内部类

### 6.2 pipe 名建议覆写

为了避免和本机现有 `rasp_sentry.exe` 冲突，建议 demo 默认使用独立 pipe 名：

```cpp
config.rulesPipeName = LR"(\\.\pipe\amsi_detect_rules_demo)";
config.eventsPipeName = LR"(\\.\pipe\amsi_detect_events_demo)";
config.controlStatusPipeName = LR"(\\.\pipe\amsi_detect_control_status_demo)";
config.configPipeName = LR"(\\.\pipe\amsi_detect_config_demo)";
```

说明：

- 生产默认 pipe 名不变
- demo/测试环境建议覆写 pipe 名，避免和现有进程抢占通道
- 如果后续要和真实 DLL 联调，可再切回正式 pipe 名或同步修改 DLL 指向 demo pipe

---

## 7. 程序启动流程

建议 `main.cpp` 流程如下：

1. 构造 `HostGuardFileRuleProvider`
2. 构造 `HostGuardJsonlEventSink`
3. 构造 `HostGuardJsonlControlStatusSink`
4. 使用 `AmsiIpcHostConfig::ForHostGuard()`
5. 构造 `AmsiIpcHostAdapters`
6. 创建 `AmsiIpcHost`
7. 调用 `host.Start()`
8. 进入命令循环
9. 收到 `quit` 后 `host.Stop()` 并退出

示例：

```cpp
auto config = amsi_ipc::AmsiIpcHostConfig::ForHostGuard();

amsi_ipc::AmsiIpcHostAdapters adapters;
adapters.ruleProvider = &ruleProvider;
adapters.eventSink = &eventSink;
adapters.controlStatusSink = &statusSink;

amsi_ipc::AmsiIpcHost host(config, adapters);
if (!host.Start()) {
    return 1;
}
```

---

## 8. 控制台命令设计

第一版建议只支持以下命令：

### 8.1 `reload`

固定执行顺序：

```cpp
host.InvalidateRules();
host.BroadcastReload();
```

必须先 `InvalidateRules()`，再 `BroadcastReload()`。

### 8.2 `unload`

执行：

```cpp
host.BroadcastUnload();
```

### 8.3 `status`

打印：

- host 是否已启动
- 当前 rules 文件路径
- 当前日志目录
- 当前 pipe 名
- provider cache 状态
- 最近一次 reload / unload 调用结果

### 8.4 `quit`

执行：

- `host.Stop()`
- 退出进程

---

## 9. 与当前工程隔离的关键点

### 9.1 要做的

- 独立目录：`tools/hostguard_demo`
- 独立 `CMakeLists.txt`
- 独立 build 目录：`build-hostguard-demo`
- 默认独立 pipe 名
- 不依赖 `rasp_sentry.exe`
- 不依赖 demo watcher

### 9.2 不要做的

- 不把 target 混入 `rasp_sentry_native/CMakeLists.txt`
- 不 include demo-only 内部类
- 不复用 `rasp_sentry.exe` 的 main 逻辑
- 不修改 DLL / wire protocol

---

## 10. 第一版验收标准

第一版只要求证明最小联调闭环可运行：

1. `hostguard_demo.exe` 可独立启动和退出
2. `status` 命令可显示当前配置
3. `reload` 调用成功，不挂死
4. `unload` 调用成功，不挂死
5. rules pipe 可返回 provider 内容
6. events pipe 写入的 payload 可进入 event sink
7. control status pipe 写入的 payload 可进入 status sink
8. 日志文件可生成
9. 与当前 `rasp_sentry.exe` 并存时不冲突（pipe 名不同）

---

## 11. 推荐实施顺序

### 第一步

先实现：

- `HostGuardFileRuleProvider`
- `HostGuardJsonlEventSink`
- `HostGuardJsonlControlStatusSink`
- `HostGuardDemoApp`

### 第二步

只起 `hostguard_demo.exe`，不接 DLL，先做 smoke test：

- `Start()`
- `status`
- `quit`

### 第三步

加本地 pipe 客户端测试：

- `GET_RULES`
- `GET_ALL_RULES`
- events payload
- control status payload

### 第四步

再加手工命令联调：

- 修改规则文件
- 输入 `reload`
- 检查 provider/cache/log 是否更新

### 第五步

最后再接真实 DLL 环境联调。

---

## 12. 推荐 target 命名

建议 target 名称直接使用：

```text
hostguard_demo
```

不建议使用：

- `hostguard`
- `edr_host`
- `hostguard_service`

原因：

- 避免和未来正式 HostGuard 模块混淆
- 清楚表达“联调程序”定位

---

## 13. 最终建议

当前最合适的落地形式是：

- 新增一个完全独立的 `tools/hostguard_demo` 小工程
- 单独 CMake
- 单独编译
- 默认独立 pipe 名
- 只依赖 `AmsiIpcHost` 和三类注入接口
- 注入 file-backed rule provider 和两个 JSONL sink
- 用控制台命令实现：
  - `reload`
  - `unload`
  - `status`
  - `quit`

第一版先手动 `reload`，不要先做 watcher。

---

## 14. 一句话总结

`hostguard_demo.exe` 的最小方案，应是一个**完全独立、单独编译、只依赖 façade 和三个注入接口的 HostGuard 风格联调程序**，用于验证：不依赖 `rasp_sentry.exe`，也能完整跑通规则拉取、reload、事件上报、控制状态上报和 unload 广播。

---

## 15. 下一阶段实施方案与关键约束

本节记录第一版 demo 落地后的下一阶段实施约束。已知本地测试环境无 `sentry.exe` 运行，因此可以加入正式 pipe 名联调，但必须保持严格失败语义，不能为了测试便利静默降级。

### 15.1 pipe 模式参数

建议新增运行模式参数：

```powershell
hostguard_demo.exe .\config\rasp_rules.json .\logs --demo-pipes
hostguard_demo.exe .\config\rasp_rules.json .\logs --production-pipes
```

语义：

- `--demo-pipes`：使用 `_demo` pipe 名，适合 smoke test 和快速回归。
- `--production-pipes`：使用正式 pipe 名，适合替代 `rasp_sentry.exe` 做真实 HostGuard/DLL 联调。

正式 pipe 名固定为：

```text
\\.\pipe\amsi_detect_rules
\\.\pipe\amsi_detect_events
\\.\pipe\amsi_detect_control_status
\\.\pipe\amsi_detect_config
```

### 15.2 `--production-pipes` 严格模式硬约束

一旦指定 `--production-pipes`：

- 必须只使用正式 pipe 名。
- 绝不能静默 fallback 到 `_demo` pipe。
- 如果正式 pipe 已存在服务端或无法创建，程序必须明确失败并打印错误。
- 失败时应直接退出，不进入命令循环。

示例：

```powershell
hostguard_demo.exe .\config\rasp_rules.json .\logs --production-pipes
```

如果 `\\.\pipe\amsi_detect_rules` 等正式 pipe 已被其它进程占用，该命令应报错退出，而不是自动切换到 `\\.\pipe\amsi_detect_rules_demo`。

这是下一阶段最重要的行为约束。`--production-pipes` 的目标是暴露真实环境冲突，而不是隐藏冲突。

### 15.3 `hostguard_demo_pipe_client.exe`

建议新增独立 pipe client 工具：

```text
hostguard_demo_pipe_client.exe
```

该工具不是普通调试器，而是 DLL 的最小替身，必须严格复刻当前 wire 语义。

#### rules pipe

发送内容必须为：

```text
GET_RULES\n
GET_ALL_RULES\n
```

要求：

- 命令必须带结尾换行。
- 不额外发送其它字段。
- 读取服务端响应时按当前 rules pipe 行为处理。

#### event pipe / control status pipe

发送行为：

- 原样写 payload。
- 不追加额外换行。
- 不修改 JSON。
- 不做 escape / unescape。
- 不格式化、不压缩、不重排字段。

原因：如果 pipe client 比真实 DLL 更宽容或更“聪明”，测试结果会失真，可能出现 pipe client 能通但真实 DLL 不能通的情况。

建议命令：

```powershell
hostguard_demo_pipe_client.exe rules GET_RULES
hostguard_demo_pipe_client.exe rules GET_ALL_RULES
hostguard_demo_pipe_client.exe event "{\"test\":1}"
hostguard_demo_pipe_client.exe status "{\"msgType\":\"RULE_LOAD_RESULT\"}"
```

后续可增加参数切换 pipe 模式：

```powershell
hostguard_demo_pipe_client.exe --demo-pipes rules GET_RULES
hostguard_demo_pipe_client.exe --production-pipes rules GET_RULES
```

pipe client 必须要求显式 pipe 模式，不允许默认猜测 `_demo` 或正式 pipe。缺少 `--demo-pipes` / `--production-pipes` 时，应直接打印 usage 并返回失败。

### 15.4 手工联调脚本与自动化脚本分层

下一阶段脚本分为两类。

#### A. 手工联调脚本

用于测试机或本地人工联调，可以依赖控制台输入。

建议脚本名：

```text
scripts/run_hostguard_demo_manual_test.ps1
```

当前定位：

- 不是全自动脚本。
- `reload` / `unload` / `quit` 仍通过 `hostguard_demo.exe` 控制台命令触发。
- 适合观察 console 输出、日志文件和 DLL 侧行为。

建议流程：

1. 启动 `hostguard_demo.exe --production-pipes`。
2. 用 `hostguard_demo_pipe_client.exe --production-pipes rules GET_RULES` 验证规则拉取。
3. 用 pipe client 写入 event payload。
4. 用 pipe client 写入 control status payload。
5. 检查 JSONL 日志。
6. 人工输入 `reload`。
7. 修改规则文件后再次 `GET_RULES`。
8. 人工输入 `unload`。
9. 人工输入 `quit`。

#### B. 自动化脚本

后续再补，不作为当前阶段的第一优先级。

自动化脚本要求：

- 不依赖人工控制台输入。
- 能自动启动和停止 `hostguard_demo.exe`。
- 能自动触发 reload / unload / quit。
- 能作为 opt-in 回归测试运行。

在自动化脚本完成前，文档和 README 必须明确：当前手工脚本不是 CI 级全自动回归脚本。

### 15.5 production pipe 测试必须 opt-in

建议新增测试 target：

```text
hostguard_demo_production_pipe_tests
```

但该测试不能默认进入最常规 smoke / 快速回归测试集。

原因：

- 正式 pipe 是否空闲依赖本机环境。
- 本机可能已有其它 host 进程占用 pipe。
- 权限和安全描述符可能随运行上下文变化。

要求：

- 标记为 integration / manual / opt-in 测试。
- 运行前先检测正式 pipe 是否可用。
- 如果 pipe 被占用，必须明确提示哪个 pipe 被占用。
- 如果权限不足，必须明确提示权限问题。
- 不允许静默跳过后返回“成功”。

建议命令示例：

```powershell
cmake --build build-hostguard-demo --config Release --target hostguard_demo_production_pipe_tests
.\build-hostguard-demo\Release\hostguard_demo_production_pipe_tests.exe
```

### 15.6 DLL 联调前检查项

接真实 DLL 前，必须先满足以下 3 个前提。

#### 前提 1：production pipe 独立闭环已通过

`hostguard_demo.exe --production-pipes` 已能独立处理：

- `GET_RULES`
- `GET_ALL_RULES`
- event payload
- control status payload

这些验证应先由 `hostguard_demo_pipe_client.exe --production-pipes` 完成。

#### 前提 2：reload / unload 可重复执行

控制台命令：

```text
reload
unload
```

必须可重复执行，不挂死、不崩溃。

#### 前提 3：日志路径稳定可写

日志目录必须可写，并且以下文件能稳定生成：

```text
rasp-events-YYYY-MM-DD.jsonl
rasp-control-status-YYYY-MM-DD.jsonl
```

以上三项任一不满足时，不应接真实 DLL。

### 15.7 `status` 输出增强

为了降低手工联调排障成本，`status` 命令至少输出：

- 当前模式：`demo` / `production`
- 当前 rules pipe 名
- 当前 events pipe 名
- 当前 control status pipe 名
- 当前 config pipe 名
- 当前 rules 文件路径
- 当前日志目录
- provider cache 状态
- 最近一次 `reload` 结果
- 最近一次 `unload` 结果
- 是否启用 demo config watcher
- 是否启用 demo staging watcher
- 是否处于 strict HostGuard mode

实现时，`strictHostGuardMode` 必须放在 `status` 输出前几行醒目显示，不能埋在长列表末尾。该字段用于快速判断当前是否误跑进 demo fallback。

在 `--production-pipes` 下，`status` 输出必须能清楚证明当前没有使用 `_demo` pipe。

### 15.8 推荐下一步实施顺序

1. 增加 pipe mode 参数：`--demo-pipes` / `--production-pipes`。
2. 为 `--production-pipes` 增加严格失败语义：正式 pipe 被占用时启动失败。
3. 增强 `status` 输出，展示模式、pipe 名、watcher/strict 状态。
4. 新增 `hostguard_demo_pipe_client.exe`，严格复刻 DLL wire 语义。
5. 新增手工联调脚本，明确不是全自动脚本。
6. 新增 opt-in 的 `hostguard_demo_production_pipe_tests`。
7. 满足 DLL 联调前检查项后，再接真实 DLL。
