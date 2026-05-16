# Batch 4 ControlStatusChannel 抽离设计

## 1. 当前阶段

当前主线已经完成：

- Batch 1：配置广播 `AmsiConfigBroadcaster` 抽离。
- Batch 2：规则请求 `AmsiRuleChannel` / `IAmsiRuleProvider` 抽离。
- Batch 3：事件通道 `AmsiEventChannel` / `IAmsiEventSink` 抽离。

Batch 4 只处理 `amsi_detect_control_status` 通道，把 `ControlStatusCollector` 中的 pipe worker 和 payload 读取逻辑迁入 `amsi_ipc_host`。本批不改变 `RULE_LOAD_RESULT` schema，不改变 JSONL 落盘，不改变 DLL 侧发送逻辑。

## 2. 目标

本批目标：

- 新增 `AmsiControlStatusChannel`。
- 新增 `IAmsiControlStatusSink`。
- 让 `ControlStatusCollector` 实现 sink 接口。
- 复用 `NamedPipeServerPool` 管理 pipe worker。
- 保持 `amsi_detect_control_status` pipe 名称不变。
- 保持 `ControlStatusCollector::kThreadCount == 2`。
- 保持 `rasp-control-status-YYYY-MM-DD.jsonl` 落盘行为不变。

## 3. 非目标

本批明确不做：

- 不修改 `RULE_LOAD_RESULT` JSON schema。
- 不新增 HostGuard / EDR SDK 接入。
- 不合并 events 与 control status 通道。
- 不改变 reload / unload 决策。
- 不改变 `RuleServer`。
- 不改变 `EventCollector`。
- 不改变 DLL 侧 `SendControlStatus` 或等价发送路径。
- 不新增 retry / backoff / async queue。

## 4. 新增接口

### 4.1 `amsi_control_status_sink.h`

路径：

```text
src/amsi_ipc_host/include/amsi_control_status_sink.h
```

建议定义：

```cpp
#pragma once

#include <string>

namespace amsi_ipc {

struct AmsiControlStatusLine {
    std::string payload;
};

class IAmsiControlStatusSink {
public:
    virtual ~IAmsiControlStatusSink() = default;
    virtual void OnControlStatusLine(const AmsiControlStatusLine& status) = 0;
};

} // namespace amsi_ipc
```

边界要求：

- DTO 只承载 raw payload。
- 不表达 `RULE_LOAD_RESULT` 字段语义。
- 不 include `control_status_collector.h`。
- 不 include HostGuard / EDR SDK。

### 4.2 `amsi_control_status_channel.h/.cpp`

路径：

```text
src/amsi_ipc_host/include/amsi_control_status_channel.h
src/amsi_ipc_host/src/amsi_control_status_channel.cpp
```

职责：

- 实现 `INamedPipeClientHandler`。
- 从 pipe 读取单段 payload。
- `bytesRead == 0` 或 `ReadFile()` 失败时不调用 sink。
- 成功读取后调用 `IAmsiControlStatusSink::OnControlStatusLine()`。

禁止：

- 不解析 JSON。
- 不识别 `RULE_LOAD_RESULT`。
- 不写 JSONL。
- 不追加换行。
- 不 split line。
- 不支持单连接多消息 framing。
- 不访问 reload / unload 状态。

## 5. ControlStatusCollector 改造

### 5.1 目标形态

修改文件：

```text
src/rasp_sentry_native/include/control_status_collector.h
src/rasp_sentry_native/src/control_status_collector.cpp
```

目标结构：

```cpp
class ControlStatusCollector : public amsi_ipc::IAmsiControlStatusSink {
public:
    static constexpr const wchar_t* kPipeName = amsi_ipc::kControlStatusPipeName;
    static constexpr int kThreadCount = 2;

    explicit ControlStatusCollector(std::string logDir);
    ~ControlStatusCollector();

    void Start();
    void Stop();

    void OnControlStatusLine(const amsi_ipc::AmsiControlStatusLine& status) override;

private:
    void AppendLine(const std::string& jsonLine);

    std::string m_logDir;
    bool m_started = false;
    CRITICAL_SECTION m_fileLock;

    amsi_ipc::AmsiControlStatusChannel m_statusChannel;
    amsi_ipc::NamedPipeServerPool m_statusPipePool;
};
```

生命周期约束：

- `m_statusChannel` 必须先于 `m_statusPipePool` 构造完成。
- `m_statusPipePool` 只能持有已存在的 handler 引用。
- `Stop()` 必须先停止 `m_statusPipePool`。
- 停止 pool 后才能删除 `m_fileLock`。
- 不允许 pool 线程在 `ControlStatusCollector` 析构后继续访问 sink 或文件锁。

### 5.2 需要移除的旧职责

从 `ControlStatusCollector` 中移除或停止使用：

- `std::atomic<bool> m_running`
- `HANDLE m_threads[kThreadCount]`
- `ThreadProc`
- `ServerLoop`
- 直接 `CreateNamedPipeW`
- 直接 `ConnectNamedPipe`

### 5.3 保留的业务职责

`ControlStatusCollector` 继续负责：

- 尾部 trim 行为。
- 空 payload 丢弃。
- `AppendLine()` 写入 `rasp-control-status-YYYY-MM-DD.jsonl`。
- 文件锁 `m_fileLock`。
- 当前日志输出行为。

如果旧 `ServerLoop()` 存在如下逻辑：

```cpp
while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' '))
    line.pop_back();
```

则必须迁入 `OnControlStatusLine()`，不能放进 channel。

trim 硬约束：

- 只能照搬旧逻辑，移除尾部 `\n` / `\r` / space。
- 不允许顺手扩展为 `\t`、Unicode whitespace、前后双向 trim 或 JSON-aware trim。
- trim 后为空时继续丢弃，不调用 `AppendLine()`。

## 6. NamedPipeServerPool 使用

`ControlStatusCollector` 应按 inbound-only 旧语义构造 pool：

```cpp
m_statusPipePool(amsi_ipc::kControlStatusPipeName,
                 kThreadCount,
                 m_statusChannel,
                 0,
                 65536,
                 PIPE_ACCESS_INBOUND,
                 GENERIC_WRITE)
```

要求：

- 依赖 Batch 3 中 `NamedPipeServerPool` 的 `openMode` / `dummyClientAccess` 参数。
- 不改变 pipe type：继续使用 message mode / wait mode。
- 不扩大或缩小旧读取 buffer，实施前以当前 `ControlStatusCollector::ServerLoop()` 为准。

## 7. Wire 行为

Batch 4 必须保持：

- 单连接读取一段 payload。
- 不支持单连接多消息。
- channel 不追加 `\n`。
- channel 不 trim。
- sink 层保留旧 trim。
- trim 后为空时不调用 `AppendLine()`。
- payload 不是 JSON 时，channel 仍原样透传。
- `RULE_LOAD_RESULT` 解析或业务判断不在 channel 层发生。

## 8. 测试计划

### 8.1 新增测试

新增：

```text
src/amsi_ipc_host/tests/amsi_control_status_channel_tests.cpp
```

测试目标：

- 普通 `RULE_LOAD_RESULT` payload 原样到达 fake sink。
- channel 不追加换行。
- channel 不裁剪 payload 中间已有换行。
- 非 JSON payload 原样透传。
- UTF-8 字节不变形。
- empty payload 不调用 sink。
- 多次 `HandleClient()` 产生多条独立 payload。

建议使用匿名 pipe 单测，避免真实 named pipe 时序导致 flake。

匿名 pipe 单测边界：

- 只覆盖 channel seam。
- 只证明 payload 原样透传、empty payload 不调用 sink、不解析 JSON、不追加换行。
- 不能替代真实 named pipe / `NamedPipeServerPool` 集成回归。

### 8.2 回归测试

必须运行：

```powershell
cmake --build src\rasp_sentry_native\build-codex --config Release --target amsi_control_status_channel_tests
.\src\rasp_sentry_native\build-codex\Release\amsi_control_status_channel_tests.exe

cmake --build src\rasp_sentry_native\build-codex --config Release --target amsi_event_channel_tests
.\src\rasp_sentry_native\build-codex\Release\amsi_event_channel_tests.exe

cmake --build src\rasp_sentry_native\build-codex --config Release --target amsi_rule_channel_tests
.\src\rasp_sentry_native\build-codex\Release\amsi_rule_channel_tests.exe

cmake --build src\rasp_sentry_native\build-codex --config Release --target amsi_config_broadcaster_tests
.\src\rasp_sentry_native\build-codex\Release\amsi_config_broadcaster_tests.exe

cmake --build src\rasp_sentry_native\build-codex --config Release --target rasp_sentry
git diff --check
```

测试机验收还需要确认：

- DLL 发送 `RULE_LOAD_RESULT` 后，EXE 仍写入 `rasp-control-status-YYYY-MM-DD.jsonl`。
- control status 通道真实 named pipe 可被 DLL 侧旧发送路径连接。
- `rasp_sentry.exe` 正常启动、停止，不出现 Stop 挂死。

## 9. CMake 修改

修改：

```text
src/rasp_sentry_native/CMakeLists.txt
```

生产 target 增加：

```cmake
../amsi_ipc_host/src/amsi_control_status_channel.cpp
```

新增测试 target：

```cmake
add_executable(amsi_control_status_channel_tests
    ../amsi_ipc_host/tests/amsi_control_status_channel_tests.cpp
    ../amsi_ipc_host/src/amsi_control_status_channel.cpp
)
```

## 10. 静态门禁

Batch 4 完成后应满足：

- `ControlStatusCollector` 不再直接调用 `CreateNamedPipeW`。
- `ControlStatusCollector` 不再直接调用 `ConnectNamedPipe`。
- `ControlStatusCollector` 不再直接管理 `HANDLE m_threads[kThreadCount]`。
- `AmsiControlStatusChannel` 不 include `control_status_collector.h`。
- `AmsiControlStatusChannel` 不出现 `RULE_LOAD_RESULT`。
- `AmsiControlStatusChannel` 不出现 `rasp-control-status`。
- `AmsiControlStatusChannel` 不出现 JSON 字段名。
- `AmsiControlStatusChannel` 不出现 reload / unload 业务语义。
- `AmsiControlStatusChannel` 不写文件。
- `NamedPipeServerPool` 不出现 control status 业务字符串。

## 11. 实施顺序

1. 新增 `amsi_control_status_sink.h`。
2. 新增 `amsi_control_status_channel.h/.cpp`。
3. 新增 `amsi_control_status_channel_tests.cpp`。
4. 更新 `CMakeLists.txt`。
5. 先跑 `amsi_control_status_channel_tests.exe`。
6. 改造 `ControlStatusCollector` 为 `IAmsiControlStatusSink`。
7. 保持 `AppendLine()` 不变。
8. 构建 `rasp_sentry.exe`。
9. 跑 Batch 1/2/3 IPC 回归测试。
10. `git diff --check`。

## 12. 回滚策略

Batch 4 必须独立提交。

如出现 control status 接收异常：

- revert Batch 4 commit。
- 恢复 `ControlStatusCollector::ServerLoop()` 旧实现。
- 不影响 Batch 1/2/3 的配置、规则、事件通道抽离结果。
