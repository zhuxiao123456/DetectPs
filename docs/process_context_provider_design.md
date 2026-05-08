# ProcessContextProvider 设计方案

## 1. 当前阶段与目标

当前 AMSI 检测链路只能获取 `appName`、`contentName`、当前进程 PID/TID 和脚本内容，不能获取调用 PowerShell 的父进程名称。本文设计新增独立 `ProcessContextProvider` 组件，用于采集当前 AMSI 宿主进程和父进程上下文，并将父进程摘要注入检测上下文和事件输出。

本方案只描述设计，不直接修改代码。

## 2. 设计原则

- `ProcessContextProvider` 是独立组件，不放入 `AmsiRuleEngine` 或 `RaspSentryBase`。
- 父进程采集失败不阻断 `Scan()`，不改变 AMSI 返回语义。
- 成功采集后缓存为不可变快照，不做 TTL 周期刷新。
- 首次采集失败允许有限次数退避重试。
- 内部状态使用枚举，不依赖字符串比较。
- `RaspEvalResult` 只携带规则和事件都需要的进程摘要，不承载完整调试字段。
- full path 字段默认不输出，只能由调试开关控制进入事件构造层。

## 3. 目标调用链

```text
CRaspAmsiProvider::Scan()
  -> ProcessContextProvider::GetSnapshot()
  -> 构造 ScanContext
  -> AmsiRuleEngine::Evaluate(contentName, appName, sample, sampleLen, scanContext)
  -> RaspLuaContext.fields 注入 parentPid / parentProcessName / processCaptureStatus
  -> Regex / Lua 检测
  -> RaspEvalResult 携带 parent 摘要
  -> EventJsonBuildInput 聚合事件字段
  -> EventJsonBuilder 输出 parentPid / parentProcessName
```

## 4. 新增文件建议

```text
src/rasp_mod_amsi/include/process_context_provider.h
src/rasp_mod_amsi/src/process_context_provider.cpp
src/rasp_mod_amsi/include/scan_context.h
src/rasp_mod_amsi/tests/process_context_provider_tests.cpp
```

`process_context_provider.*` 只负责采集和缓存进程上下文。

`scan_context.h` 只定义单次扫描上下文 DTO，不负责采集、不负责缓存、不依赖 AMSI COM。

## 5. 核心类型设计

### 5.1 ProcessCaptureStatus

内部状态使用枚举：

```cpp
enum class ProcessCaptureStatus : uint8_t {
    Uninitialized,
    Initializing,
    Success,
    NtdllUnavailable,
    NtQuerySymbolUnavailable,
    PpidQueryFailed,
    ParentPidZero,
    ParentSystem,
    ParentOpenDenied,
    ParentProcessExited,
    ParentPathQueryFailed,
    InternalError
};
```

序列化到 Lua / JSON 时再映射为稳定字符串，例如：

```text
success
initializing
ntdll-unavailable
ntquery-symbol-unavailable
ppid-query-failed
parent-open-denied
```

禁止在核心逻辑中用字符串比较判断状态。

接口必须提供：

```cpp
const char* ProcessCaptureStatusToString(ProcessCaptureStatus status);
const char* ProcessRetryStateToString(ProcessRetryState state);
ProcessContextProvider& GetProcessContextProvider();
```

这三个接口是 Batch 2 接入规则上下文的前置依赖。

### 5.2 ProcessContextSnapshot

```cpp
struct ProcessContextSnapshot {
    DWORD currentPid = 0;
    std::string currentProcessName;
    std::string currentProcessPath;

    DWORD parentPid = 0;
    std::string parentProcessName;
    std::string parentProcessPath;

    ProcessCaptureStatus status = ProcessCaptureStatus::Uninitialized;
    ProcessErrorDomain errorDomain = ProcessErrorDomain::None;
    uint32_t nativeError = 0;
    ProcessRetryState retryState = ProcessRetryState::None;

    bool valid = false;
    bool parentResolved = false;
};
```

字段语义：

| 字段 | 语义 |
|---|---|
| `valid` | 快照结构是否可用于检测上下文。必须满足下方 `valid=true` 最小条件。 |
| `parentResolved` | 父进程元数据是否成功解析到名称或明确的 System 状态。 |
| `status` | 当前根因状态或采集阶段，内部用枚举。失败时不得被 retry 状态覆盖。 |
| `retryState` | 当前是否等待重试或已耗尽重试。 |
| `errorDomain` | `nativeError` 的来源域，例如 `Win32` 或 `NtStatus`。 |
| `nativeError` | 平台原生错误码。`Win32` 与 `NtStatus` 不混写，必须由 `errorDomain` 区分。 |

`valid=true` 的硬性最小条件：

```text
currentPid != 0
currentProcessName 非空
currentProcessPath 非空，或至少已能从可用路径/模块名中稳定提取 basename
```

如果当前进程 PID 或当前进程名无法确定，快照不得标记为 `valid=true`。父进程解析失败不影响 `valid`，只影响 `parentResolved` 和 `status`。

进程名规范：

- `currentProcessName` / `parentProcessName` 保留原始文件名大小写，不强制 lower-case。
- `parentPid == 4` 时固定输出 `System`。
- 不可得时使用空字符串 `""`。
- 禁止混用 `unknown`、`<unknown>`、`<unavailable>`、`<exited>` 等多风格 sentinel。

`valid` 和 `parentResolved` 不等价。示例：

```text
当前 PID / 当前路径成功，父 PID 成功，但 OpenProcess(parentPid) 失败：
valid = true
parentResolved = false
status = ParentOpenDenied
parentPid = queried parent pid
parentProcessName = ""
```

### 5.3 ScanContext

```cpp
struct ScanContext {
    const ProcessContextSnapshot* process = nullptr;
    bool emitProcessPathFields = false;
};
```

`ScanContext` 由 `CRaspAmsiProvider::Scan()` 构造并传给 `AmsiRuleEngine::Evaluate()`。

## 6. ProcessContextProvider 行为

### 6.1 推荐接口

```cpp
class ProcessContextProvider {
public:
    const ProcessContextSnapshot& GetSnapshot();

private:
    bool TryCapture(ProcessContextSnapshot& out);
};
```

### 6.2 快照缓存语义

成功采集后：

- 缓存为不可变快照。
- 后续 `GetSnapshot()` 直接返回该快照。
- 不做 TTL 周期刷新。
- 内部承载对象建议使用 `std::shared_ptr<const ProcessContextSnapshot>` 或等效不可变对象。
- 成功快照一旦发布，不再原地修改。

失败采集后：

- 缓存失败快照，而不是裸返回空对象。
- 失败快照包含根因 `status`、`retryState`、`errorDomain`、`nativeError`、当前进程可用字段。
- 允许有限次数退避重试。

### 6.3 并发语义修正

不建议“锁竞争时直接返回 empty snapshot”。推荐两级逻辑：

1. 已有成功快照时，走快路径返回成功快照。
2. 首次采集阶段，只允许一个线程执行采集。
3. 其他线程返回当前缓存快照：
   - `status = Initializing`
   - 或 `retryState = Pending`
   - 或最近一次失败快照。

这样规则层和事件层可以区分：

- 进程上下文正在初始化
- 最近一次采集失败，等待重试
- 父进程解析失败
- 采集成功

避免扫描高峰期出现同一进程中一部分请求有 parent、一部分请求完全 empty 的语义抖动。

### 6.4 重试策略

建议默认：

```text
maxFailedAttempts = 3
retry backoff = 1s -> 5s -> 30s
```

退避时间源要求：

- 使用 `GetTickCount64()` 或等效单调时钟。
- 禁止使用 wall clock / system time 参与重试判断。
- 系统时间回拨或 NTP 校时不得影响 `nextRetryTickMs_`。

状态转换：

```text
Uninitialized
  -> Initializing
  -> Success

Initializing
  -> root-cause status + retryState=Pending
  -> root-cause status + retryState=Exhausted

root-cause status + retryState=Pending
  -> Initializing
  -> Success
  -> root-cause status + retryState=Exhausted
```

成功采集后的状态清理要求：

- 立即清零 `failedAttempts_`。
- 立即清零 `nextRetryTickMs_`。
- 立即将 `retryState` 设为 `None`。
- `snapshot_` 固化为成功快照后，不再进入重试路径。
- 后续 `GetSnapshot()` 只返回成功快照，除非显式 reset/reinitialize。

重试耗尽后：

- 返回 `valid` 可用程度最高的失败快照。
- 不阻断 `Scan()`。
- 不触发复杂日志或 IPC。

## 7. Windows 采集实现

### 7.1 当前进程

使用：

```cpp
GetCurrentProcessId();
GetModuleFileNameW(nullptr, ...);
```

提取：

- `currentPid`
- `currentProcessPath`
- `currentProcessName`

当前进程路径采集要求：

- 使用与父进程路径一致的长缓冲策略。
- 第一版建议使用 32768 wchar 缓冲。
- 如果返回长度触及缓冲上限，按路径查询失败处理，不截断 basename。

### 7.2 父 PID

使用：

```cpp
NtQueryInformationProcess(
    GetCurrentProcess(),
    ProcessBasicInformation,
    ...
)
```

要求：

- 从 `ntdll.dll` 动态 `GetProcAddress("NtQueryInformationProcess")`。
- 自定义最小 `PROCESS_BASIC_INFORMATION` 结构，避免 SDK 差异。
- `ntdll.dll` 不可用时设置 `status = NtdllUnavailable`。
- `NtQueryInformationProcess` 符号不可用时设置 `status = NtQuerySymbolUnavailable`。
- API 调用返回非 0 `NTSTATUS` 时设置 `status = PpidQueryFailed`，并记录 `errorDomain = NtStatus`。

### 7.3 父进程路径与名称

使用：

```cpp
OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, parentPid);
QueryFullProcessImageNameW(...);
```

处理：

| 场景 | 结果 |
|---|---|
| `parentPid == 0` | `status = ParentPidZero`, `parentResolved = false` |
| `parentPid == 4` | `parentProcessName = "System"`, `parentResolved = true`, `status = ParentSystem` |
| `OpenProcess` 返回 NULL 且 `GetLastError() == ERROR_ACCESS_DENIED` | `status = ParentOpenDenied`, 保留 `parentPid` |
| `OpenProcess` 返回 NULL 且 `GetLastError() == ERROR_INVALID_PARAMETER` 或等价退出语义 | `status = ParentProcessExited`, 保留 `parentPid` |
| `OpenProcess` 返回 NULL 且错误原因无法归类 | `status = InternalError`，保留 `parentPid` |
| `QueryFullProcessImageNameW` 失败 | `status = ParentPathQueryFailed` |
| 成功 | `parentResolved = true`, `status = Success` |

`ParentPathQueryFailed` 与 `InternalError` 的边界：

- 可归因于 `QueryFullProcessImageNameW` 失败的路径查询错误，使用 `ParentPathQueryFailed`。
- Provider 自身逻辑异常、不可达分支、状态不变量破坏、无法归类的内部错误，使用 `InternalError`。

## 8. AmsiProvider 接入设计

当前：

```cpp
AmsiEvalResult eval = engine->Evaluate(contentName, appName, evalSample, evalLen);
```

目标：

```cpp
const ProcessContextSnapshot& process = GetProcessContextProvider().GetSnapshot();

ScanContext scanContext;
scanContext.process = process.valid ? &process : nullptr;
scanContext.emitProcessPathFields = IsProcessPathDebugEnabled();

AmsiEvalResult eval = engine->Evaluate(
    contentName,
    appName,
    evalSample,
    evalLen,
    scanContext);
```

`IsProcessPathDebugEnabled()` 第一版可为编译期常量或配置读取，默认 `false`。

## 9. AmsiRuleEngine 接入设计

新增重载：

```cpp
AmsiEvalResult Evaluate(
    const wchar_t* contentName,
    const wchar_t* appName,
    const char* sample,
    ULONG sampleLen,
    const ScanContext& scanContext);
```

旧签名可保留为兼容包装：

```cpp
AmsiEvalResult Evaluate(
    const wchar_t* contentName,
    const wchar_t* appName,
    const char* sample,
    ULONG sampleLen)
{
    ScanContext empty;
    return Evaluate(contentName, appName, sample, sampleLen, empty);
}
```

注入到 `RaspLuaContext.fields`：

```cpp
parentPid
parentProcessName
processCaptureStatus
```

可选注入：

```cpp
currentPid
currentProcessName
```

默认不注入：

```cpp
currentProcessPath
parentProcessPath
```

除非 `scanContext.emitProcessPathFields == true`。

## 10. RaspEvalResult 字段边界

根据 review 意见，`RaspEvalResult` 不应成为“检测结果 + 全量事件上下文容器”。

建议只增加规则消费和事件默认输出都需要的摘要字段：

```cpp
DWORD parentPid = 0;
std::string parentProcessName;
ProcessCaptureStatus processCaptureStatus = ProcessCaptureStatus::Uninitialized;
```

如需避免 `rasp_rule_engine` 依赖 `ProcessCaptureStatus` 枚举，也可以在传入 `RaspEvalResult` 时转为：

```cpp
std::string processCaptureStatus;
```

但核心状态仍应在 `ProcessContextProvider` 内部保持枚举。

不建议放入 `RaspEvalResult`：

```cpp
currentProcessPath
parentProcessPath
emitProcessPathFields
```

这些属于事件输出细节，应在事件构造层根据 `ScanContext` / debug 开关决定是否进入 `EventJsonBuildInput`。

## 11. EventJsonBuilder 字段设计

`EventJsonBuildInput` 可以聚合更多事件字段：

```cpp
DWORD parentPid = 0;
std::string parentProcessName;
std::string processCaptureStatus;

std::string currentProcessPath; // debug only
std::string parentProcessPath;  // debug only
bool emitProcessPathFields = false;
```

默认 JSON 输出：

```json
"parentPid": 1234,
"parentProcessName": "cmd.exe",
"processCaptureStatus": "success"
```

仅调试开关开启时输出：

```json
"currentProcessPath": "...",
"parentProcessPath": "..."
```

路径字段默认关闭，原因：

- 路径可能包含用户名、目录结构等敏感信息。
- 父进程名和 PID 已足够支撑大多数检测和告警关联。
- 避免事件体膨胀。

## 12. 失败与降级策略

父进程采集失败时：

- 不阻断 `Scan()`。
- 不返回 `AMSI_RESULT_DETECTED`。
- 不跳过脚本内容检测。
- 不写阻塞 pipe。
- 不等待 EDR。
- 不触发复杂 telemetry。

检测上下文仍包含：

```text
processCaptureStatus = "ppid-query-failed" / "ntdll-unavailable" / ...
processRetryState = "pending" / "exhausted" / "none"
parentPid = 0 或已知 parentPid
parentProcessName = ""
```

事件或规则层如需表达重试状态，应使用独立 `processRetryState` 字段，不能把 `processCaptureStatus` 覆盖为 `retry-pending` / `retry-exhausted`。`processCaptureStatus` 必须保留根因，例如 `ntdll-unavailable`、`ppid-query-failed`、`parent-open-denied`。

规则可以选择：

- 仅在 `parentProcessName` 非空时做父进程规则。
- 在 `processCaptureStatus != success` 时忽略父进程条件。
- `processCaptureStatus` 只能作为规则降级、跳过或审计补充条件，不能单独作为 `block` 条件。

原因：采集失败是环境状态，不是攻击信号。禁止编写类似“`processCaptureStatus != success` 即高危阻断”的规则，避免将权限、父进程退出、系统 API 异常等环境噪声转化为误报源。

## 13. 性能与线程安全要求

`Scan()` 热路径禁止：

- 遍历全进程列表。
- 使用 `CreateToolhelp32Snapshot` 作为主路径。
- 长时间持锁。
- 等待其他线程采集完成。
- 同步写 pipe / EDR event bus / 磁盘日志。

`ProcessContextProvider` 要求：

- 成功快照返回路径尽量无系统调用。
- 首次采集只允许单线程执行。
- 其他线程返回 `Initializing` 或失败快照，不返回裸 empty。
- 成功快照不可变。
- 失败重试有上限。

## 14. 测试方案

建议通过 Win32 API seam 做 fake 测试，避免依赖真实父进程环境。

### ProcessContextProvider 单测

覆盖：

1. 当前进程路径提取 basename。
2. 父 PID 查询成功。
3. 父进程路径查询成功。
4. `parentPid == 4` 映射为 `System`。
5. `OpenProcess` 失败时 `valid = true`、`parentResolved = false`。
6. 失败状态使用 enum，不依赖字符串。
7. 首次成功后 snapshot 不刷新。
8. 首次失败后返回根因失败快照，且 `retryState = Pending`。
9. 锁竞争时不返回裸 empty snapshot。
10. 重试耗尽后保留根因状态，且 `retryState = Exhausted`。
11. 多线程并发 `GetSnapshot()` 不崩溃。

### AmsiRuleEngine 接入测试

覆盖：

1. `parentPid` / `parentProcessName` 进入 `RaspLuaContext.fields`。
2. 规则可以匹配 `parentProcessName == "cmd.exe"`。
3. `processCaptureStatus` 可见。
4. `scanContext.process == nullptr` 时回退普通脚本检测。
5. `scanContext.process != nullptr` 但 `process.valid == false` 时不崩溃，body 规则仍然执行，且规则能看到 `processCaptureStatus` / `processRetryState` 降级字段。

### EventJsonBuilder 测试

覆盖：

1. 默认输出 `parentPid` / `parentProcessName`。
2. 默认不输出 `currentProcessPath` / `parentProcessPath`。
3. debug 开启时输出路径字段。
4. `ProcessCaptureStatus` 字符串化稳定。

## 15. 分批实施建议

### Batch 1：独立组件与测试

允许：

- 新增 `process_context_provider.h/.cpp`
- 新增 `process_context_provider_tests.cpp`
- 新增 enum/string mapper

禁止：

- 不接 `AmsiProvider`
- 不改 `AmsiRuleEngine`
- 不改事件 JSON

### Batch 2：ScanContext 与规则上下文

允许：

- 新增 `scan_context.h`
- `CRaspAmsiProvider::Scan()` 获取 snapshot
- `AmsiRuleEngine::Evaluate(..., scanContext)` 注入规则字段

`scan_context.h` 应使用前置声明，避免把 `process_context_provider.h` 传播到所有包含方：

```cpp
#pragma once

struct ProcessContextSnapshot;

struct ScanContext {
    const ProcessContextSnapshot* process = nullptr;
    bool emitProcessPathFields = false;
};
```

禁止：

- 不输出路径字段到事件
- 不接 EDR SDK
- 不改变 AMSI 返回策略

### Batch 3：事件 JSON 输出

允许：

- `RaspEvalResult` 增加 parent 摘要字段
- `EventJsonBuildInput` 增加事件字段
- `EventJsonBuilder` 默认输出 parent 摘要
- debug 开关控制 path 字段

禁止：

- 不默认输出 full path
- 不把 `RaspEvalResult` 扩成全量事件上下文

### Batch 4：规则与回归验证

允许：

- 增加测试规则覆盖父进程名称匹配。
- 增加事件 golden 测试。
- 增加并发和失败回退测试。

禁止：

- 不做祖先进程链。
- 不做 ETW 进程缓存。

## 16. 明确不做

本阶段不做：

- 完整祖先进程链。
- ETW 进程创建缓存。
- WMI 查询。
- `CreateToolhelp32Snapshot` 主路径。
- Scan 热路径远程查询 EDR。
- 默认输出完整进程路径。
- 父进程采集失败后 fail-close。
- 将 `ProcessContextProvider` 放入 `AmsiRuleEngine` 或 `RaspSentryBase`。

## 17. 最小下一步任务

建议下一步只做：

1. 保存本文档。
2. 评审 `ProcessContextSnapshot` 的字段语义。
3. 评审 `ProcessCaptureStatus` 枚举。
4. 评审 `RaspEvalResult` 和 `EventJsonBuildInput` 的字段分界。

评审通过后再进入 Batch 1，实现独立 `ProcessContextProvider` 和单元测试。
