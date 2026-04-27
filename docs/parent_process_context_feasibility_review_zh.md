# AMSI 父进程上下文采集能力实现可行性审查报告

**审查日期**: 2026-04-26  
**审查对象**: `DetectPsByAmsi` AMSI 检测模块  
**审查结论**: 现有代码不支持父进程信息采集，需新增完整采集模块

---

## 一、当前调用链分析

### 1.1 完整调用链路图

```
┌─────────────────────────────────────────────────────────────────────────────┐
│ PowerShell.exe 执行脚本                                                       │
│   ↓ Windows AMSI 组件调用 IAntimalwareProvider::Scan()                       │
├─────────────────────────────────────────────────────────────────────────────┤
│ amsi_provider.cpp:88-224                                                     │
│   CRaspAmsiProvider::Scan(IAmsiStream *stream, AMSI_RESULT *result)         │
│   ├── stream->GetAttribute(AMSI_ATTRIBUTE_APP_NAME) → appName (宿主进程名)   │
│   ├── stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_NAME) → contentName       │
│   ├── stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_ADDRESS) → 脚本内容        │
│   └── g_engine->Evaluate(contentName, appName, evalSample, evalLen)         │
│       │                                                                      │
│       │  【关键入口点】函数签名：                                              │
│       │  AmsiEvalResult Evaluate(const wchar_t*, const wchar_t*,            │
│       │                           const char*, ULONG)                       │
│       │                                                                      │
├─────────────────────────────────────────────────────────────────────────────┤
│ amsi_rule_engine.cpp:411-442                                                │
│   AmsiRuleEngine::Evaluate(wchar_t*, wchar_t*, char*, ULONG)                 │
│   ├── WideToUtf8(contentName) → contentNameUtf8                             │
│   ├── WideToUtf8(appName) → appNameUtf8                                     │
│   └── 构建 RaspLuaContext:                                                   │
│       ctx.fields = {                                                         │
│           {"contentName", contentNameUtf8},                                  │
│           {"appName", appNameUtf8},                                          │
│           {"body", sample, isBinary=true}                                    │
│       }                                                                      │
│   └── 调用内部 Evaluate("AmsiProvider", ctx)                                 │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│ amsi_rule_engine.cpp:264-402                                                │
│   AmsiRuleEngine::Evaluate(sensor, ctx) [override]                          │
│   ├── 加载 m_snapshot 规则列表                                               │
│   ├── 逐规则匹配：regexChecks / regexPatterns / Lua script                   │
│   └── 匹配成功时构建 RaspEvalResult:                                          │
│       RaspEvalResult r;                                                      │
│       r.matched = true;                                                      │
│       r.block = rule.IsBlock();                                             │
│       r.ruleId = rule.id;                                                   │
│       r.sensor = "AmsiProvider";                                            │
│       r.desc = desc;                                                         │
│       r.payload = payload;                                                   │
│       r.severity = rule.severity;                                           │
│       r.contentName = contentNameUtf8;    ← 从 ctx.fields 提取               │
│       r.appName = appNameUtf8;            ← 从 ctx.fields 提取               │
│       r.confidence = rule.confidence;                                       │
│   └── SendDetectionEvent(r)                                                 │
│       results.push_back(std::move(r));                                       │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│ rasp_sentry_base.cpp:516-553                                                │
│   RaspSentryBase::SendDetectionEvent(RaspEvalResult)                        │
│   ├── 构建 JSONL:                                                            │
│       {"id":"...", "ts":"...", "sev":"...", "act":"block/audit",            │
│        "cat":"Detection", "mod":"rasp_mod_amsi", "sensor":"AmsiProvider",   │
│        "rule":"...", "desc":"...",                                          │
│        "appName":"powershell.exe", "contentName":"...",                     │
│        "confidence":"70", "ip":"", "ua":"", "pattern":"..."}                │
│   └── WriteFile to \\.\pipe\rasp_sentry_events                             │
│                                                                              │
├─────────────────────────────────────────────────────────────────────────────┤
│ event_collector.cpp:95-186                                                  │
│   EventCollector::ServerLoop()                                               │
│   ├── CreateNamedPipeW("\\.\pipe\rasp_sentry_events")                       │
│   ├── ReadFile → JSONL line                                                 │
│   └── AppendLine → rasp-events-{YYYY-MM-DD}.jsonl                          │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.2 关键数据结构流转

```
IAmsiStream → appName/contentName → RaspLuaContext.fields → RaspEvalResult → JSONL → event_collector
```

### 1.3 当前缺陷

整个链路 **完全没有父进程 PID 或名字的获取、传递、存储和输出**。

---

## 二、需要修改的文件清单

### 2.1 必须修改的文件（核心链路）

| 文件路径 | 修改内容 | 影响范围 |
|---------|---------|---------|
| `src/rasp_rule_engine/include/rasp_sentry_base.h:43-58` | 扩展 `RaspEvalResult` 结构体，新增父进程字段 | 所有模块共享 |
| `src/rasp_rule_engine/src/rasp_sentry_base.cpp:516-553` | 扩展 `SendDetectionEvent()` JSONL 输出 | 所有模块共享 |
| `src/rasp_mod_amsi/src/amsi_provider.cpp:88-224` | `Scan()` 中调用进程上下文采集 | AMSI 入口 |
| `src/rasp_mod_amsi/include/amsi_rule_engine.h:63-67` | 扩展 `Evaluate()` 公共接口签名 | AMSI 公共 API |
| `src/rasp_mod_amsi/src/amsi_rule_engine.cpp:411-442` | 扩展 `Evaluate()` 实现，传递进程上下文 | AMSI 内部 |

### 2.2 推荐新增的文件

| 文件路径 | 内容 |
|---------|-----|
| `src/rasp_mod_amsi/include/process_context.h` | `ProcessContext` 结构体 + 函数声明 |
| `src/rasp_mod_amsi/src/process_context.cpp` | 父进程 PID/路径采集实现 |

### 2.3 可选修改的文件（增强功能）

| 文件路径 | 修改内容 |
|---------|---------|
| `src/rasp_rule_engine/include/rasp_lua_engine.h:54-59` | 扩展 `RaspLuaContext` 增加进程上下文字段（供 Lua 规则使用） |
| `src/rasp_rule_engine/src/rasp_lua_engine.cpp` | `Run()` 中注入进程上下文到 Lua table |

---

## 三、推荐新增的数据结构

### 3.1 ProcessContext 结构体（新增）

```cpp
// src/rasp_mod_amsi/include/process_context.h

#pragma once
#include <windows.h>
#include <string>

struct ProcessContext
{
    // 当前进程信息
    DWORD       currentPid        = 0;
    std::string currentProcessName;
    std::string currentProcessPath;
    
    // 父进程信息
    DWORD       parentPid         = 0;
    std::string parentProcessName;
    std::string parentProcessPath;
    
    // 采集状态
    std::string captureError;      // "success" / "ppid-failed" / "path-failed" / "access-denied"
    DWORD       captureTimestamp   = 0;  // GetTickCount()，用于判断缓存新鲜度
    
    // 采集方法
    void Capture();                // 完整采集
    void CaptureCurrentOnly();     // 仅采集当前进程（轻量）
    void Clear();                  // 清空字段
    
    // 工具方法
    static std::string WideToUtf8(const std::wstring& w);
    static std::string ExtractNameFromPath(const std::string& path);
};
```

### 3.2 扩展 RaspEvalResult（修改现有）

```cpp
// src/rasp_rule_engine/include/rasp_sentry_base.h

struct RaspEvalResult
{
    // === 现有字段（保持不变）===
    bool        matched   = false;
    bool        block     = false;
    std::string ruleId;
    std::string sensor;
    std::string desc;
    std::string payload;
    std::string severity;
    std::string contentName;
    std::string appName;
    std::string ip;
    std::string ua;
    int         confidence;
    
    // === 新增：进程上下文 ===
    DWORD       currentPid         = 0;
    std::string currentProcessName;
    std::string currentProcessPath;
    
    DWORD       parentPid          = 0;
    std::string parentProcessName;
    std::string parentProcessPath;
    std::string processCaptureError;  // 采集失败原因
};
```

### 3.3 扩展 RaspLuaContext（可选，供 Lua 规则使用）

```cpp
// src/rasp_rule_engine/include/rasp_lua_engine.h

struct RaspLuaContext
{
    std::vector<RaspLuaField>        fields;
    const std::vector<std::string>*  arrayField      = nullptr;
    std::string                      arrayFieldName;
    
    // === 新增：进程上下文指针（可选填充）===
    const ProcessContext*            processContext  = nullptr;  // AMSI 模块可填充
};
```

---

## 四、推荐 API 实现方案

### 4.1 父进程 PID 获取方式对比

| 方式 | 性能 | 权限要求 | 兼容性 | 复杂度 | 推荐度 |
|-----|-----|---------|-------|-------|-------|
| **NtQueryInformationProcess** | **最优**（单次调用，~0.1ms） | 无特殊权限 | Win XP+ | 低 | **★★★★★** |
| CreateToolhelp32Snapshot | 中等（遍历进程列表，~5-50ms） | 无特殊权限 | Win XP+ | 中 | ★★★☆☆ |
| WMI (IWbemServices) | 较差（异步 COM 调用，~100-500ms） | 需要 WMI 服务可用 | Win XP+ | 高 | ★★☆☆☆ |
| ETW | 不适用（实时事件流，不适合即时查询） | 需要 ETW Session | Win 7+ | 很高 | ☆☆☆☆☆ |

**推荐：NtQueryInformationProcess**

理由：
1. AMSI Scan 是高频调用（每个脚本片段），性能至关重要
2. 无需遍历整个进程列表
3. 只需要获取当前进程的父 PID，单次 API 调用即可
4. 权限要求最低（只查询自己）

### 4.2 父进程路径解析方式对比

| 方式 | 权限 | 失败场景 | 兼容性 | 推荐度 |
|-----|-----|---------|-------|-------|
| **OpenProcess + QueryFullProcessImageNameW** | PROCESS_QUERY_LIMITED_INFORMATION | 进程已退出 / 权限隔离 / System 进程 | Win Vista+ | **★★★★★** |
| OpenProcess + GetModuleFileNameExW | PROCESS_QUERY_INFORMATION + PROCESS_VM_READ | 权限要求更高，32/64 位跨架构需 WOW64 处理 | Win XP+ | ★★★☆☆ |
| CreateToolhelp32Snapshot + PROCESSENTRY32 | 无额外权限，但需要遍历 | 进程已退出时无法获取路径 | Win XP+ | ★★☆☆☆ |

**推荐：OpenProcess + QueryFullProcessImageNameW**

理由：
1. `PROCESS_QUERY_LIMITED_INFORMATION` 是最低权限，跨 Session 可用
2. Win Vista+ 全支持，现代 Windows 系统（包括 Server 2012+）均支持
3. 不需要 VM READ 权限，避免安全软件拦截
4. 返回完整路径而非仅文件名

### 4.3 核心实现代码

```cpp
// src/rasp_mod_amsi/src/process_context.cpp

#include "process_context.h"
#include <winternl.h>

// ===== NtQueryInformationProcess 声明 =====
// winternl.h 定义不完整，需手动补充
typedef NTSTATUS (NTAPI *PFN_NTQUERYINFORMATIONPROCESS)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength OPTIONAL);

// Windows SDK 的 PROCESS_BASIC_INFORMATION 缺少父 PID 字段
struct RASP_PROCESS_BASIC_INFORMATION {
    PVOID   Reserved1;
    PVOID   PebBaseAddress;
    PVOID   Reserved2[2];
    ULONG   UniqueProcessId;
    ULONG   InheritedFromUniqueProcessId;  // ← 父进程 PID
};

static PFN_NTQUERYINFORMATIONPROCESS GetNtQueryInfoProcess() {
    static PFN_NTQUERYINFORMATIONPROCESS fn = nullptr;
    if (!fn) {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (hNtdll) {
            fn = (PFN_NTQUERYINFORMATIONPROCESS)
                GetProcAddress(hNtdll, "NtQueryInformationProcess");
        }
    }
    return fn;
}

// ===== 父进程 PID 获取 =====
static DWORD GetParentProcessId_Native() {
    auto fn = GetNtQueryInfoProcess();
    if (!fn) return 0;
    
    RASP_PROCESS_BASIC_INFORMATION pbi = {};
    ULONG returnLength = 0;
    
    NTSTATUS status = fn(
        GetCurrentProcess(),
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength);
    
    if (status != 0) return 0;  // NTSTATUS != STATUS_SUCCESS
    return pbi.InheritedFromUniqueProcessId;
}

// ===== 父进程路径获取 =====
static std::wstring GetProcessPath_ByHandle(DWORD pid) {
    if (pid == 0 || pid == 4) {
        // PID 0 = Idle, PID 4 = System
        return pid == 4 ? L"System" : L"Idle";
    }
    
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        pid);
    
    if (!hProcess) {
        DWORD err = GetLastError();
        // 5 = ACCESS_DENIED, 87 = INVALID_PARAMETER (进程已退出)
        return L"";  // 返回空表示失败
    }
    
    WCHAR path[1024] = {};
    DWORD size = 1024;
    
    BOOL ok = QueryFullProcessImageNameW(hProcess, 0, path, &size);
    CloseHandle(hProcess);
    
    return ok ? std::wstring(path) : L"";
}

// ===== ProcessContext 实现 =====
void ProcessContext::Capture() {
    captureTimestamp = GetTickCount();
    captureError = "success";
    
    // 1. 当前进程信息（必定成功）
    currentPid = GetCurrentProcessId();
    
    WCHAR curPath[1024] = {};
    GetModuleFileNameW(nullptr, curPath, 1024);
    currentProcessPath = WideToUtf8(curPath);
    currentProcessName = ExtractNameFromPath(currentProcessPath);
    
    // 2. 父进程 PID
    parentPid = GetParentProcessId_Native();
    if (parentPid == 0) {
        captureError = "ppid-query-failed";
        parentProcessName = "<unknown>";
        return;
    }
    
    // 3. 父进程路径
    std::wstring pParentPath = GetProcessPath_ByHandle(parentPid);
    if (pParentPath.empty()) {
        // 可能是进程已退出、权限不足、或 System 进程
        if (parentPid == 4) {
            parentProcessName = "System";
            parentProcessPath = "C:\\Windows\\System.exe";  // 概念路径
        } else {
            captureError = "parent-process-unavailable";
            parentProcessName = "<exited-or-denied>";
        }
        return;
    }
    
    parentProcessPath = WideToUtf8(pParentPath);
    parentProcessName = ExtractNameFromPath(parentProcessPath);
}

void ProcessContext::CaptureCurrentOnly() {
    captureTimestamp = GetTickCount();
    captureError = "current-only";
    
    currentPid = GetCurrentProcessId();
    WCHAR curPath[1024] = {};
    GetModuleFileNameW(nullptr, curPath, 1024);
    currentProcessPath = WideToUtf8(curPath);
    currentProcessName = ExtractNameFromPath(currentProcessPath);
    
    parentPid = 0;
    parentProcessName.clear();
    parentProcessPath.clear();
}

void ProcessContext::Clear() {
    currentPid = 0;
    currentProcessName.clear();
    currentProcessPath.clear();
    parentPid = 0;
    parentProcessName.clear();
    parentProcessPath.clear();
    captureError.clear();
    captureTimestamp = 0;
}

std::string ProcessContext::WideToUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1,
                                   nullptr, 0, nullptr, nullptr);
    if (len <= 0) return {};
    std::string s(len - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], len, nullptr, nullptr);
    return s;
}

std::string ProcessContext::ExtractNameFromPath(const std::string& path) {
    if (path.empty()) return {};
    size_t pos = path.find_last_of("\\/");
    if (pos == std::string::npos) return path;
    return path.substr(pos + 1);
}
```

---

## 五、风险点分析

### 5.1 编译风险

| 风险点 | 描述 | 解决方案 |
|-------|-----|---------|
| `winternl.h` 定义不完整 | Windows SDK 的 `PROCESS_BASIC_INFORMATION` 缺少 `InheritedFromUniqueProcessId` | 自定义 `RASP_PROCESS_BASIC_INFORMATION` 结构体 |
| `NtQueryInformationProcess` 未声明 | `winternl.h` 只有声明但无导入库 | 使用 `GetProcAddress` 动态获取 |
| `QueryFullProcessImageNameW` Win XP 不支持 | XP 无此 API | 项目目标为现代 Windows（Vista+），可忽略；备选 `GetModuleFileNameExW` |

### 5.2 运行时崩溃风险

| 风险点 | 描述 | 解决方案 |
|-------|-----|---------|
| NtQueryInformationProcess 失败返回值 | NTSTATUS 非 0 表示失败，需要检查 | `if (status != 0) return 0;` |
| OpenProcess 返回 NULL | 进程已退出或权限不足 | `if (!hProcess) return L"";` |
| 父进程为 System (PID=4) | OpenProcess 对 System 进程返回 ACCESS_DENIED | 特殊处理 PID 0/4 |
| 进程路径含非 ASCII | 路径可能有 Unicode 字符 | 使用 `WideCharToMultiByte(CP_UTF8)` |
| 多线程并发访问缓存 | 缓存的 ProcessContext 需要线程安全 | 使用 `std::atomic` 或 CRITICAL_SECTION |

### 5.3 性能风险

| 场景 | 影响 | 优化方案 |
|-----|-----|---------|
| 高频 AMSI Scan | 每次 Scan 都采集父进程会有 ~0.1-1ms 开销 | DLL 加载时采集一次并缓存 |
| 进程 respawn | PowerShell 可能被 respawn，父进程变化 | 缓存 TTL（如 30 秒）或检测到 respawn 时重新采集 |
| 大量脚本片段 | PowerShell 复杂脚本会产生 10+ 次 Scan | 缓存复用，避免重复采集 |

### 5.4 权限失败风险

| 场景 | 描述 | 解决方案 |
|-------|-----|---------|
| 父进程已退出 | OpenProcess 失败，返回 ACCESS_DENIED | 记录 `parentProcessName = "<exited>"`，不阻塞检测 |
| 父进程是高权限进程 | 如以 SYSTEM 运行的父进程 | `PROCESS_QUERY_LIMITED_INFORMATION` 是最低权限，通常可用 |
| 跨 Session 隔离 | AMSI 在用户 Session，父进程在 Session 0 | `PROCESS_QUERY_LIMITED_INFORMATION` 跨 Session 允许 |
| 安全软件拦截 | 某些 EDR 会拦截 OpenProcess | 使用最低权限，记录失败原因 |

### 5.5 32/64 位兼容性

| 场景 | 描述 | 解决方案 |
|-------|-----|---------|
| 当前项目 x64 编译 | CMakeLists.txt 指定 x64 | 父进程也可能是 64 位，无问题 |
| 父进程为 32 位 | WOW64 进程 | `QueryFullProcessImageNameW` 正确处理，返回真实路径 |
| 未来需要 x86 编译 | PROCESS_BASIC_INFORMATION 结构体大小不同 | 需要区分编译目标，当前 x64 无此问题 |

---

## 六、缓存策略分析

### 6.1 DLL 加载时采集 vs 每次 Scan 时采集

| 策略 | 优点 | 缺点 | 推荐场景 |
|-------|-----|-----|---------|
| **DLL 加载时采集一次** | 性能最优（0 开销） | 无法感知父进程变化 | **推荐默认方案** |
| Scan 时采集 + 缓存 TTL | 可检测父进程变化 | TTL 内可能有脏数据 | 进程 respawn 可能的场景 |
| 每次 Scan 都采集 | 数据最准确 | 性能开销大（高频 Scan 不适合） | 不推荐 |

### 6.2 推荐策略：DLL 加载时采集 + 可选 TTL 刷新

```cpp
// 全局缓存
static ProcessContext g_cachedProcessContext;
static std::atomic<bool> g_contextCached{false};
static const DWORD kCacheTtlMs = 30000;  // 30 秒 TTL

// 获取缓存的进程上下文（带 TTL）
const ProcessContext& GetCachedProcessContext() {
    DWORD now = GetTickCount();
    
    if (!g_contextCached.load() ||
        (now - g_cachedProcessContext.captureTimestamp > kCacheTtlMs)) {
        g_cachedProcessContext.Capture();
        g_contextCached.store(true);
    }
    
    return g_cachedProcessContext;
}

// DLL 加载时初始化（DllMain DLL_PROCESS_ATTACH）
void InitProcessContext() {
    g_cachedProcessContext.Capture();
    g_contextCached.store(true);
}
```

**理由**：
- PowerShell 通常不会在运行时改变父进程
- AMSI DLL 加载绑定到 PowerShell 进程生命周期
- 30 秒 TTL 足够覆盖短暂 respawn 场景
- 性能开销几乎为零

---

## 七、最小可落地版本

### 7.1 目标：仅增加父进程 PID 和名字，不修改 Lua 层

**修改文件**：
1. `src/rasp_mod_amsi/include/process_context.h`（新增）
2. `src/rasp_mod_amsi/src/process_context.cpp`（新增）
3. `src/rasp_rule_engine/include/rasp_sentry_base.h`（扩展 RaspEvalResult）
4. `src/rasp_rule_engine/src/rasp_sentry_base.cpp`（扩展 SendDetectionEvent）
5. `src/rasp_mod_amsi/src/amsi_provider.cpp`（调用采集）
6. `src/rasp_mod_amsi/src/rasp_mod_amsi.cpp`（DllMain 初始化缓存）

### 7.2 具体修改

#### 7.2.1 新增 process_context.h

```cpp
#pragma once
#include <windows.h>
#include <string>

struct ProcessContext {
    DWORD       currentPid = 0;
    std::string currentProcessName;
    DWORD       parentPid = 0;
    std::string parentProcessName;
    std::string captureError;
    
    void Capture();
};

extern ProcessContext g_cachedProcessContext;
void InitProcessContext();
```

#### 7.2.2 新增 process_context.cpp

```cpp
#include "process_context.h"

ProcessContext g_cachedProcessContext;

void InitProcessContext() {
    g_cachedProcessContext.Capture();
}

void ProcessContext::Capture() {
    // 实现见上文 4.3
}
```

#### 7.2.3 扩展 RaspEvalResult

```cpp
// rasp_sentry_base.h

struct RaspEvalResult {
    // 现有字段...
    
    // 新增（最小版本）
    DWORD       currentPid = 0;
    std::string currentProcessName;
    DWORD       parentPid = 0;
    std::string parentProcessName;
};
```

#### 7.2.4 扩展 SendDetectionEvent

```cpp
// rasp_sentry_base.cpp:SendDetectionEvent()

json << "\"currentPid\":\"" << result.currentPid << "\","
     << "\"currentProcessName\":\"" << SentryJsonEscape(result.currentProcessName) << "\","
     << "\"parentPid\":\"" << result.parentPid << "\","
     << "\"parentProcessName\":\"" << SentryJsonEscape(result.parentProcessName) << "\","
     << "\"parentProcessError\":\"" << SentryJsonEscape(result.processCaptureError) << "\",";
```

#### 7.2.5 amsi_provider.cpp 修改

```cpp
// amsi_provider.cpp:Scan() 函数末尾

IFACEMETHODIMP CRaspAmsiProvider::Scan(IAmsiStream *stream, AMSI_RESULT *result) {
    // ... 现有代码 ...
    
    AmsiEvalResult eval = g_engine->Evaluate(
        contentName, appName, evalSample, evalLen);
    
    // 新增：进程上下文已在外部通过 g_cachedProcessContext 获取
    // 由 AmsiRuleEngine::Evaluate 内部填充到 RaspEvalResult
    
    // ... 现有返回逻辑 ...
}
```

#### 7.2.6 amsi_rule_engine.cpp 修改

```cpp
// amsi_rule_engine.cpp:Evaluate() 内部

std::vector<RaspEvalResult> AmsiRuleEngine::Evaluate(const std::string& sensor, const RaspLuaContext& ctx) {
    // ... 规则匹配逻辑 ...
    
    RaspEvalResult r;
    // 现有字段填充...
    
    // 新增：填充进程上下文（从全局缓存）
    const ProcessContext& pc = g_cachedProcessContext;
    r.currentPid = pc.currentPid;
    r.currentProcessName = pc.currentProcessName;
    r.parentPid = pc.parentPid;
    r.parentProcessName = pc.parentProcessName;
    r.processCaptureError = pc.captureError;
    
    SendDetectionEvent(r);
    results.push_back(std::move(r));
}
```

#### 7.2.7 DllMain 初始化

```cpp
// rasp_mod_amsi.cpp

#include "process_context.h"

BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        g_hModule = hinstDLL;
        DisableThreadLibraryCalls(hinstDLL);
        
        // 新增：初始化进程上下文缓存
        InitProcessContext();
        
        // 现有引擎初始化...
        g_engine = new AmsiRuleEngine();
        g_engine->Initialize();
    }
    // ...
}
```

---

## 八、后续增强版本

### 8.1 增强点：完整进程路径 + Lua 规则支持 + 动态刷新

**新增字段**：
- `currentProcessPath`
- `parentProcessPath`
- `processCaptureTimestamp`

**Lua 规则支持**：
```cpp
// RaspLuaContext 扩展
struct RaspLuaContext {
    std::vector<RaspLuaField> fields;
    const ProcessContext* processContext = nullptr;  // 可选
};

// rasp_lua_engine.cpp:Run() 中注入
if (ctx.processContext) {
    // 创建 Lua table: context.process
    lua_newtable(L);
    lua_pushinteger(L, ctx.processContext->currentPid);
    lua_setfield(L, -2, "currentPid");
    lua_pushstring(L, ctx.processContext->currentProcessName.c_str());
    lua_setfield(L, -2, "currentProcessName");
    // ... parentPid, parentProcessName, parentProcessPath
    lua_setfield(L, -2, "process");  // context.process = {...}
}
```

**Lua 规则示例**：
```lua
-- 规则脚本可以利用父进程信息
function rule(sensor, context)
    -- 检测 cmd.exe 启动的 PowerShell 执行敏感命令
    if context.process and context.process.parentProcessName == "cmd.exe" then
        if context.body:find("Invoke-Expression") then
            return {matched=true, desc="cmd→PowerShell suspicious", payload="cmd-parent"}
        end
    end
    return {matched=false}
end
```

### 8.2 增强点：进程链追踪

**记录更多祖先进程**（需多次 OpenProcess）：
```cpp
struct ProcessChain {
    std::vector<ProcessContext> ancestors;  // 最大深度 3-5
    void CaptureChain(int maxDepth = 3);
};
```

### 8.3 增强点：ETW 实时监控

**独立 ETW Consumer**：
- 监听 `Microsoft-Windows-Kernel-Process` 事件
- 实时记录进程创建关系
- AMSI 检测时查询 ETW 缓存而非实时 OpenProcess

---

## 九、总结

| 维度 | 最小版本 | 增强版本 |
|-----|---------|---------|
| **字段** | currentPid, currentProcessName, parentPid, parentProcessName | +currentProcessPath, +parentProcessPath, +processCaptureError |
| **性能** | ~0 开销（DLL 加载时一次采集） | 同最小版本 |
| **Lua 支持** | 无 | processContext 注入到 Lua table |
| **代码改动量** | ~6 个文件，~200 行新增代码 | ~8 个文件，~400 行新增代码 |
| **风险** | 低 | 低-中（Lua 注入需测试） |

**推荐实施路径**：
1. 先实现最小版本，验证基本功能
2. 收集实际场景数据，评估父进程信息价值
3. 根据需求决定是否升级到增强版本