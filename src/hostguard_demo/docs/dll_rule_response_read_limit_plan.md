# 规则响应 2MB 下发与 DLL 循环读取优化方案

## 评审结论

本方案接受当前检视意见，并将实现前文档收敛点纳入设计。

核心结论：

1. 最大限制统一为 **wire payload 字节数**，包含服务端追加的尾随 `\n`。
2. 最大 wire payload 限制为 `2 * 1024 * 1024` 字节。
3. HostGuard 侧和 DLL 侧必须使用同一限制口径：wire bytes。
4. 服务端检查必须发生在 `wire = response.json + "\n"` 构造之后、`WriteFile` 之前。
5. DLL 侧按累计读取到的 wire bytes 判断是否超过上限。
6. 服务端是否需要把 rule pipe out buffer 从 512KB 提升到 2MB，由 spike 对照结果决定。
7. `ReadOnePipeChunk` 必须显式处理 `ERROR_MORE_DATA + partial bytes`，不能复用当前有语义缺陷的 `ReadPipeWithTimeout()`。
8. 当前服务端 rule channel 存在同步读、同步写和 `FlushFileBuffers` 阻塞风险，需要在 spike 中验证并登记为 P1 风险。

## 背景

当前 AMSI DLL 通过规则管道拉取规则：

```text
\\.\pipe\amsi_detect_rules
```

请求内容为：

```text
GET_ALL_RULES\n
```

当前实现存在两处 512KB 级别的限制点：

1. HostGuard / sentry native 侧规则管道 out buffer 为 512KB。
2. DLL 侧 `ConnectSentry()` 读取规则响应时固定分配 512KB，并且只读取一次。

随着规则逐渐增多，完整规则响应可能超过 512KB。此时可能出现：

- HostGuard 侧规则响应写入失败。
- DLL 侧只读取到部分响应。
- JSON 被截断导致解析失败。
- reload 失败或启动时规则不可用。

需要注意：线上实际写入的不是纯 JSON，而是：

```cpp
std::string wire = response.json + "\n";
```

因此本方案统一按 wire payload 字节数计算限制，而不是按 JSON 字节数计算限制。

## 目标

1. 最大规则响应限制为 wire payload 最大 2MB，包含尾随 `\n`。
2. DLL 侧不再使用固定 512KB 单次读取。
3. DLL 侧支持 message pipe 的 `ERROR_MORE_DATA` 循环读取。
4. DLL 侧必须正确保留每次 partial read 的字节数，不丢 chunk。
5. DLL 侧按累计 wire bytes 设置 2MB 硬上限，超过限制直接拒绝。
6. DLL 侧循环读取设置全局截止时间，避免初始化或 reload 被长时间阻塞。
7. HostGuard 侧写入前检查 wire payload 大小，超过 2MB 时拒绝，不写截断内容。
8. 是否提升 HostGuard rule pipe out buffer 由 spike 结果决定。
9. 不打印规则内容，不打印正则内容，只打印长度、chunk 数、错误码等元信息。
10. 保持现有 wire protocol，不增加长度头，不改变 `GET_ALL_RULES\n` 请求语义。

## 非目标

本阶段不做：

- 不增加 `LEN <bytes>` 协议头。
- 不做规则差量更新。
- 不做 hash 命中跳过。
- 不做按模块拉取规则。
- 不改变规则 JSON 格式。
- 不改变规则解析语义。
- 不把 2MB 上限做成客户可见策略项。
- 不做按当前规则包实际大小动态重建 pipe buffer。

允许修改：

- HostGuard 侧规则响应写入前长度检查。
- 必要时修改 HostGuard 侧规则 pipe out buffer 常量。
- DLL 侧规则响应读取 helper。

不允许修改：

- `GET_ALL_RULES\n` 请求内容。
- 规则响应 JSON 格式。
- 现有 pipe 名称。
- 业务侧策略字段。

## 当前相关代码

### HostGuard 侧规则管道

文件：

```text
src/rasp_sentry_native/src/rule_server.cpp
```

当前常量：

```cpp
constexpr DWORD kRulePipeOutBufferBytes = 512 * 1024;
constexpr DWORD kRulePipeInBufferBytes = 256;
```

`kRulePipeOutBufferBytes` 是规则服务端向 DLL 返回规则响应的 pipe out buffer 大小。

### 规则响应写入链路

存在两份 `AmsiRuleChannel` 实现，长度检查必须同时覆盖：

```text
src/amsi_ipc_host/src/amsi_rule_channel.cpp
src/module_amsi_detect/amsi_ipc_host/src/AmsiRuleChannel.cpp
```

说明：

- `src/amsi_ipc_host/src/amsi_rule_channel.cpp`：`rasp_sentry_native` / hostguard_demo / 自测链路使用。
- `src/module_amsi_detect/amsi_ipc_host/src/AmsiRuleChannel.cpp`：业务/商业版链路使用。

约束：

```text
两份必须同时加 wire 长度检查。
否则会出现自测版有保护、业务版无保护。
```

当前写入逻辑等价于：

```cpp
std::string wire = response.json + "\n";
WriteFile(pipe, wire.c_str(), expected, &written, nullptr);
FlushFileBuffers(pipe);
```

### DLL 侧规则响应读取

文件：

```text
src/rasp_rule_engine/src/rasp_sentry_base.cpp
```

当前逻辑位于 `RaspSentryBase::ConnectSentry(...)`：

```cpp
std::string response;
response.resize(524288); // 512 KB
DWORD bytesRead = 0;
DWORD readErr = 0;
BOOL ok = ReadPipeWithTimeout(hPipe,
                              &response[0],
                              (DWORD)response.size(),
                              kSentryPipeReadTimeoutMs,
                              bytesRead,
                              readErr) ? TRUE : FALSE;
```

当前 `ReadPipeWithTimeout()` 不能直接用于本方案的循环读取。

原因：

1. `ReadFile(pipe, data, len, nullptr, &ov)` 第 4 参数传 `nullptr`，同步完成时没有可靠位置接收 partial 字节数。
2. `ReadFile` 同步返回 `FALSE + ERROR_MORE_DATA` 时，当前实现会让 `bytesRead` 保持 0，导致已被 pipe 消费的 partial chunk 丢失。
3. overlapped 路径下如果最终结果是 `ERROR_MORE_DATA`，当前封装可能把它误标为 `WAIT_TIMEOUT`，导致外层无法继续读取。

因此本方案必须新增专用读取 helper，明确支持：

- `ERROR_MORE_DATA`。
- partial bytes。
- overlapped completion 后的真实错误码。
- 不把 `ERROR_MORE_DATA` 映射成 `WAIT_TIMEOUT`。

## 设计总览

本次调整分三部分：

1. 先做 spike，验证 `512KB out buffer` 和 `2MB out buffer` 两种配置下，2MB wire payload 写入和 DLL 循环读取的实际行为。
2. HostGuard 侧增加规则响应 wire payload 大小检查，超过 2MB 直接拒绝。
3. DLL 侧新增专用 message pipe 读取 helper，以 64KB chunk 循环读取，累计上限 2MB，并带全局截止时间。

整体语义：

```text
HostGuard 构造 wire = response.json + "\n"
        ↓
HostGuard 检查 wire.size() <= 2MB
        ↓
DLL 使用专用 helper 以 64KB chunk 循环读取完整 message
        ↓
遇到 ERROR_MORE_DATA 时保留当前 chunk 并继续读取
        ↓
累计 wire bytes 超过 2MB 或超过全局截止时间时失败
        ↓
读取完整后再进入 JSON 解析
```

## 限制口径

### 统一定义

最大限制按 wire payload 计算：

```text
wire = response.json + "\n"
max wire bytes = 2 * 1024 * 1024
```

推荐常量命名：

```cpp
constexpr size_t kMaxRuleWireBytes = 2 * 1024 * 1024; // wire bytes, includes trailing '\n'
```

如果实现阶段沿用旧名，也必须在注释中明确：

```cpp
constexpr size_t kMaxRuleResponseBytes = 2 * 1024 * 1024; // wire bytes, includes trailing '\n'
```

### 两侧一致性

HostGuard 侧和 DLL 侧必须一致：

```text
HostGuard kMaxRuleWireBytes == DLL kMaxRuleWireBytes == 2 * 1024 * 1024
```

两侧均按 wire 字节口径判断。

边界语义：

```text
wire.size() > 2MB  拒绝
wire.size() == 2MB 允许
wire.size() < 2MB  允许
```

由于 wire 包含尾随 `\n`：

```text
JSON 最大实际大小 = 2MB - 1 字节
```

## P0 Spike

正式实现前，先写最小 spike 验证 OS 和当前管道行为。

### 本次 Spike 结果

已新增并运行：

```text
tests/rule_pipe_large_message_spike_tests.cpp
```

验证结果：

```text
Group A: outBufferBytes = 512KB, wire payload = 2MB  通过
Group B: outBufferBytes = 2MB,   wire payload = 2MB  通过
```

运行输出：

```text
rule_pipe_large_message_spike_tests passed
groupA chunks=32 bytes=2097152 sawMoreData=1
groupB chunks=32 bytes=2097152 sawMoreData=1
```

结论：

- 512KB out buffer 已能稳定写入并由 DLL 侧按 64KB chunk 读回完整 2MB wire payload。
- 本阶段不需要把 `kRulePipeOutBufferBytes` 从 512KB 提升到 2MB。
- 只需要增加服务端写入前 wire 长度检查和 DLL 侧循环读取。

慢客户端结果：

- 客户端连接后不发送请求，会阻塞服务端同步 `ReadFile`。
- 客户端发送请求但不读取响应，会阻塞服务端同步 `WriteFile`。

处置结论：

- 该问题确认为 P1 已知风险。
- 本次最小修复不切换 rule pipe 为 overlapped，不把服务端读/写/flush 超时并入同批。
- 后续应单独立项，将 rule channel 的请求读、响应写和 flush 改为 overlapped + timeout。

### Spike 目标

验证：

1. 服务端 pipe out buffer 为 512KB 时，单次 `WriteFile` 写入 2MB wire payload 是否成功。
2. 服务端 pipe out buffer 为 2MB 时，单次 `WriteFile` 写入 2MB wire payload 是否成功。
3. 客户端以 64KB buffer 读取时，是否能收到 `ERROR_MORE_DATA`。
4. 每次 `ERROR_MORE_DATA` 是否能拿到本次 partial bytes。
5. 客户端是否能拼出完整 2MB wire payload。
6. 512KB 和 2MB out buffer 两种配置下，写入耗时、读取耗时和稳定性是否有明显差异。
7. 慢读/不读客户端是否会长时间占用 rule pipe worker。

### Spike 分组

至少包含两组对照：

```text
Group A: outBufferBytes = 512KB, wire payload = 2MB
Group B: outBufferBytes = 2MB,   wire payload = 2MB
```

可额外增加：

```text
Group C: outBufferBytes = 512KB, wire payload = 600KB
Group D: outBufferBytes = 2MB,   wire payload = 600KB
Group E: client connects but does not send request
Group F: client sends request but does not read response
Group G: client reads very slowly
```

### Spike 决策

如果 Group A 稳定通过：

```text
HostGuard rule pipe out buffer 保持 512KB
只增加服务端写入前 2MB wire 长度检查
DLL 侧循环读取最大 2MB wire bytes
```

如果 Group A 不稳定或失败，而 Group B 稳定通过：

```text
HostGuard rule pipe out buffer 固定提升到 2MB
服务端写入前 2MB wire 长度检查
DLL 侧循环读取最大 2MB wire bytes
```

如果 Group B 也失败：

```text
不能按当前方案实现
需要改为协议级分块或长度头方案
```

如果慢客户端测试显示 rule pipe worker 被明显拖住：

```text
服务端写超时并入同批实现
使用 overlapped + timeout
参考 DLL 侧 WritePipeWithTimeout 类实现
```

否则：

```text
服务端同步写阻塞登记为 P1 已知风险
后续单独优化
```

### Spike 通过标准

1. 2MB wire payload 可以完整写入和读取。
2. 客户端 chunk 拼接后内容 hash 与原始 payload hash 一致。
3. 读取过程中 `ERROR_MORE_DATA` 不导致 chunk 丢失。
4. 读取总耗时低于预期阈值。
5. spike 能回答是否真的需要把服务端 out buffer 提升到 2MB。
6. spike 能回答慢客户端是否会饿死 rule pipe worker。

## HostGuard 侧修改方案

### wire 长度检查

长度检查应放在实际写 pipe 前的 channel/handler 层。

必须覆盖两个文件：

```text
src/amsi_ipc_host/src/amsi_rule_channel.cpp
src/module_amsi_detect/amsi_ipc_host/src/AmsiRuleChannel.cpp
```

伪代码：

```cpp
constexpr size_t kMaxRuleWireBytes = 2 * 1024 * 1024; // wire bytes, includes trailing '\n'

std::string wire = response.json + "\n";
if (wire.size() > kMaxRuleWireBytes) {
    // Log length only. Do not write truncated content.
    LogRulePipeError("rule response too large",
                     wire.size(),
                     kMaxRuleWireBytes);
    return;
}

WriteFile(pipe,
          wire.data(),
          static_cast<DWORD>(wire.size()),
          &written,
          nullptr);
```

注意：

- 检查对象是 `wire.size()`，不是 `response.json.size()`。
- 禁止写截断内容。
- 日志禁止输出规则内容。

### pipe out buffer 是否提升

当前值：

```cpp
constexpr DWORD kRulePipeOutBufferBytes = 512 * 1024;
```

候选值：

```cpp
constexpr DWORD kRulePipeOutBufferBytes = 2 * 1024 * 1024;
```

最终是否修改由 spike 决定。

注意：

`CreateNamedPipeW` 的 `nOutBufferSize` 是创建 pipe instance 时的参数，不是每次响应动态设置的参数。不能按当前规则包实际大小动态调整同一个已创建 instance。

不建议做“规则更新后按当前规则包大小重建 rule pipe server”，因为会引入 worker 停止、已有连接、reload 并发和 DLL 拉取竞态。

### 内核缓冲资源影响

文件：

```text
src/amsi_ipc_host/src/named_pipe_server_pool.cpp
```

`CreateNamedPipeW` 每个 worker 会创建一个 pipe instance：

```cpp
CreateNamedPipeW(...,
                 outBufferBytes_,
                 inBufferBytes_,
                 ...);
```

如果将 out buffer 固定提升到 2MB，峰值资源风险近似为：

```text
rulePipeThreads × 2MB
```

因此 Step 1 必须确认：

- `rulePipeThreads` 默认值。
- `rulePipeThreads` 最大值。
- `rulePipeThreads × 2MB` 是否可接受。

如果 spike 证明 512KB out buffer 足够稳定支持 2MB wire payload，则不提升 pipe out buffer，以降低内核缓冲压力。

### 已知风险：服务端 worker 阻塞

当前 rule channel 存在三处同步阻塞且无超时：

1. 请求读：

```text
amsi_rule_channel.cpp: ReadFile(..., nullptr)
```

连接后不发请求的客户端可能无限期占用 worker。该路径没有 DLL 侧 10s 超时兜底，是最危险的阻塞点。

2. 响应写：

```text
amsi_rule_channel.cpp: WriteFile(..., nullptr)
```

当 wire payload 放大到 2MB 时，慢读客户端会放大 worker 阻塞窗口。DLL 侧 10s 全局读取超时只能间接兜底。

3. flush：

```text
amsi_rule_channel.cpp: FlushFileBuffers(...)
```

同样可能等待客户端读取完成。

处理策略：

- spike 必须覆盖慢读/不读客户端对 rule pipe worker 的影响。
- Step 1 必须确认 `rulePipeThreads` 默认值和最大值能否吸收少量客户端卡住 10s。
- 如果 spike 显示 worker 被明显拖住，则服务端写超时使用 overlapped + timeout 并入同批实现。
- 如果 spike 显示影响可接受，则该问题登记为 P1 已知风险，后续单独优化。

## DLL 侧修改方案

### 新增 DLL 侧读取常量

修改文件：

```text
src/rasp_rule_engine/src/rasp_sentry_base.cpp
```

新增：

```cpp
constexpr size_t kMaxRuleWireBytes = 2 * 1024 * 1024; // wire bytes, includes trailing '\n'
constexpr DWORD kRuleResponseReadChunkBytes = 64 * 1024;
constexpr DWORD kRuleResponseTotalReadTimeoutMs = 10000;
```

含义：

- `kMaxRuleWireBytes`：DLL 侧允许读取的最大 wire payload，2MB。
- `kRuleResponseReadChunkBytes`：每次读取 64KB。
- `kRuleResponseTotalReadTimeoutMs`：整条规则响应读取的全局截止时间，默认 10 秒。

设计原因：

- DLL 不一次性依赖 2MB 大读缓冲。
- 64KB chunk 便于处理 `ERROR_MORE_DATA`。
- 2MB 与 HostGuard 侧写入前 wire 长度限制保持一致。
- 全局 10 秒限制避免多个 chunk 每个等待 5 秒导致长时间阻塞。

### 使用单调时钟

全局截止时间必须使用单调时钟。

推荐：

```cpp
GetTickCount64()
```

不要使用：

```cpp
time()
std::chrono::system_clock
```

原因：

- 墙钟可能被调整。
- 夏令时或系统时间回拨会影响 deadline。
- `GetTickCount64()` ms 级精度足够覆盖 10 秒读取截止时间。

### 新增读取统计结构

在 `rasp_sentry_base.cpp` 内部新增：

```cpp
struct PipeMessageReadStats {
    DWORD chunks = 0;
    DWORD lastError = ERROR_SUCCESS;
    size_t totalBytesRead = 0;
    bool tooLarge = false;
    bool totalTimeout = false;
    bool perReadTimeout = false;
    bool sawMoreData = false;
};
```

字段说明：

- `chunks`：读取次数。
- `lastError`：最后一次读取错误码。
- `totalBytesRead`：累计读取字节数。
- `tooLarge`：是否超过 DLL 侧 2MB wire 上限。
- `totalTimeout`：是否超过全局读取截止时间。
- `perReadTimeout`：是否单次 read 超时。
- `sawMoreData`：读取过程中是否遇到过 `ERROR_MORE_DATA`。

### ReadOneChunkResult 结构

新增：

```cpp
struct ReadOneChunkResult {
    bool complete = false;
    DWORD error = ERROR_SUCCESS;
    DWORD bytesThisRead = 0;
};
```

字段说明：

- `complete=true`：当前 message 已完整读取。
- `complete=false && error == ERROR_MORE_DATA`：当前 chunk 是 partial data，外层需要 append 后继续读取。
- `complete=false && error != ERROR_MORE_DATA`：读取失败或超时。
- `bytesThisRead`：本次读取到的字节数，即使 `error == ERROR_MORE_DATA` 也可能大于 0。

### ReadOnePipeChunk 伪代码

该函数是修复 `ERROR_MORE_DATA` 语义的核心。

必须显式区分四种状态：

```cpp
ReadOneChunkResult ReadOnePipeChunk(HANDLE pipe,
                                    char* buffer,
                                    DWORD bufferBytes,
                                    DWORD timeoutMs)
{
    ReadOneChunkResult result;
    if (pipe == INVALID_HANDLE_VALUE || buffer == nullptr || bufferBytes == 0) {
        result.error = ERROR_INVALID_PARAMETER;
        return result;
    }

    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) {
        result.error = GetLastError();
        return result;
    }

    DWORD bytesThisRead = 0;
    const BOOL readOk = ReadFile(pipe,
                                 buffer,
                                 bufferBytes,
                                 &bytesThisRead,
                                 &ov);
    if (readOk) {
        CloseHandle(ov.hEvent);
        result.complete = true;
        result.error = ERROR_SUCCESS;
        result.bytesThisRead = bytesThisRead;
        return result;
    }

    DWORD err = GetLastError();

    // 状态 2：同步返回 ERROR_MORE_DATA。
    // bytesThisRead 中包含本次 partial bytes，不能丢。
    if (err == ERROR_MORE_DATA) {
        CloseHandle(ov.hEvent);
        result.complete = false;
        result.error = ERROR_MORE_DATA;
        result.bytesThisRead = bytesThisRead;
        return result;
    }

    // 状态 3：overlapped pending。
    if (err == ERROR_IO_PENDING) {
        const DWORD waitRc = WaitForSingleObject(ov.hEvent, timeoutMs);
        if (waitRc == WAIT_OBJECT_0) {
            DWORD transferred = 0;
            const BOOL overlappedOk = GetOverlappedResult(pipe,
                                                          &ov,
                                                          &transferred,
                                                          FALSE);
            if (overlappedOk) {
                CloseHandle(ov.hEvent);
                result.complete = true;
                result.error = ERROR_SUCCESS;
                result.bytesThisRead = transferred;
                return result;
            }

            const DWORD completionErr = GetLastError();

            // 关键路径：pending 完成后仍可能是 ERROR_MORE_DATA，
            // transferred 是本次 partial bytes，不能映射为 WAIT_TIMEOUT。
            if (completionErr == ERROR_MORE_DATA) {
                CloseHandle(ov.hEvent);
                result.complete = false;
                result.error = ERROR_MORE_DATA;
                result.bytesThisRead = transferred;
                return result;
            }

            CloseHandle(ov.hEvent);
            result.complete = false;
            result.error = completionErr;
            result.bytesThisRead = transferred;
            return result;
        }

        if (waitRc == WAIT_TIMEOUT) {
            CancelIo(pipe);
            DWORD ignored = 0;
            GetOverlappedResult(pipe, &ov, &ignored, TRUE);
            CloseHandle(ov.hEvent);
            result.complete = false;
            result.error = WAIT_TIMEOUT;
            result.bytesThisRead = 0;
            return result;
        }

        const DWORD waitErr = GetLastError();
        CancelIo(pipe);
        DWORD ignored = 0;
        GetOverlappedResult(pipe, &ov, &ignored, TRUE);
        CloseHandle(ov.hEvent);
        result.complete = false;
        result.error = waitErr;
        result.bytesThisRead = 0;
        return result;
    }

    // 状态 4：其它同步失败，原样上报。
    CloseHandle(ov.hEvent);
    result.complete = false;
    result.error = err;
    result.bytesThisRead = bytesThisRead;
    return result;
}
```

重点约束：

- `ReadFile` 第 4 参数必须传 `&bytesThisRead`，不能传 `nullptr`。
- `ERROR_MORE_DATA` 时 `bytesThisRead` 仍然有效，必须由外层 append。
- pending 完成后 `GetOverlappedResult == FALSE && GetLastError() == ERROR_MORE_DATA && transferred > 0` 是 partial chunk，不是超时。
- 只有 `WaitForSingleObject == WAIT_TIMEOUT` 才能设置 `WAIT_TIMEOUT`。

### ReadMessagePipeWithLimit 伪代码

新增 helper：

```cpp
bool ReadMessagePipeWithLimit(HANDLE pipe,
                              std::string& response,
                              size_t maxBytes,
                              DWORD chunkBytes,
                              DWORD perReadTimeoutMs,
                              DWORD totalTimeoutMs,
                              PipeMessageReadStats& stats)
{
    response.clear();
    stats = PipeMessageReadStats{};

    if (chunkBytes == 0 || maxBytes == 0 || totalTimeoutMs == 0) {
        stats.lastError = ERROR_INVALID_PARAMETER;
        return false;
    }

    const ULONGLONG deadline = GetTickCount64() + totalTimeoutMs;
    std::vector<char> chunk(chunkBytes);

    for (;;) {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) {
            stats.totalTimeout = true;
            stats.lastError = WAIT_TIMEOUT;
            response.clear();
            return false;
        }

        const DWORD remainingTimeout =
            static_cast<DWORD>((std::min<ULONGLONG>)(perReadTimeoutMs, deadline - now));

        const ReadOneChunkResult one = ReadOnePipeChunk(pipe,
                                                        chunk.data(),
                                                        chunkBytes,
                                                        remainingTimeout);
        ++stats.chunks;
        stats.lastError = one.error;

        if (one.bytesThisRead > 0) {
            if (response.size() + one.bytesThisRead > maxBytes) {
                stats.tooLarge = true;
                stats.totalBytesRead = response.size() + one.bytesThisRead;
                response.clear();
                return false;
            }
            response.append(chunk.data(), one.bytesThisRead);
            stats.totalBytesRead = response.size();
        }

        if (one.complete) {
            return !response.empty();
        }

        if (one.error == ERROR_MORE_DATA) {
            stats.sawMoreData = true;
            continue;
        }

        if (one.error == WAIT_TIMEOUT) {
            if (GetTickCount64() >= deadline) {
                stats.totalTimeout = true;
            } else {
                stats.perReadTimeout = true;
            }
        }

        response.clear();
        return false;
    }
}
```

timeout 语义：

- 单 chunk 等待超过 `perReadTimeoutMs` 且全局 deadline 未到：`perReadTimeout=true`。
- 因全局 deadline 被截短而超时：`totalTimeout=true`。
- 日志中必须区分 `per_read_timeout` 与 `total_timeout`。

### 替换 ConnectSentry 固定读取逻辑

将当前：

```cpp
std::string response;
response.resize(524288); // 512 KB
DWORD bytesRead = 0;
DWORD readErr = 0;
BOOL ok = ReadPipeWithTimeout(...);
```

替换为：

```cpp
std::string response;
PipeMessageReadStats readStats;
const bool ok = ReadMessagePipeWithLimit(hPipe,
                                         response,
                                         kMaxRuleWireBytes,
                                         kRuleResponseReadChunkBytes,
                                         kSentryPipeReadTimeoutMs,
                                         kRuleResponseTotalReadTimeoutMs,
                                         readStats);
CloseHandle(hPipe);

if (!ok) {
    if (readStats.tooLarge) {
        LogWithSeverity(RaspDiagSeverity::Error,
                        "ConnectSentry: rule response too large bytes=%zu limit=%zu chunks=%lu lastError=%lu sawMoreData=%d",
                        readStats.totalBytesRead,
                        kMaxRuleWireBytes,
                        readStats.chunks,
                        readStats.lastError,
                        readStats.sawMoreData ? 1 : 0);
    } else if (readStats.totalTimeout) {
        LogWithSeverity(RaspDiagSeverity::Error,
                        "ConnectSentry: rule response read total timeout timeoutMs=%lu chunks=%lu responseBytes=%zu sawMoreData=%d",
                        kRuleResponseTotalReadTimeoutMs,
                        readStats.chunks,
                        readStats.totalBytesRead,
                        readStats.sawMoreData ? 1 : 0);
    } else if (readStats.perReadTimeout) {
        LogWithSeverity(RaspDiagSeverity::Error,
                        "ConnectSentry: rule response read per-read timeout timeoutMs=%lu chunks=%lu responseBytes=%zu sawMoreData=%d",
                        kSentryPipeReadTimeoutMs,
                        readStats.chunks,
                        readStats.totalBytesRead,
                        readStats.sawMoreData ? 1 : 0);
    } else {
        LogWithSeverity(RaspDiagSeverity::Error,
                        "ConnectSentry: ReadFile failed GLE=%lu chunks=%lu responseBytes=%zu sawMoreData=%d",
                        readStats.lastError,
                        readStats.chunks,
                        readStats.totalBytesRead,
                        readStats.sawMoreData ? 1 : 0);
    }
    return false;
}
```

## 日志要求

允许输出：

```text
responseBytes
bytes
limit
chunks
lastError
sawMoreData
totalTimeout
perReadTimeout
```

禁止输出：

```text
完整规则 JSON
规则片段
正则内容
Lua 脚本内容
```

推荐日志：

```text
ConnectSentry: rule response too large bytes=2097153 limit=2097152 chunks=33 lastError=234 sawMoreData=1
```

```text
ConnectSentry: rule response read total timeout timeoutMs=10000 chunks=3 responseBytes=131072 sawMoreData=1
```

```text
ConnectSentry: rule response read per-read timeout timeoutMs=5000 chunks=1 responseBytes=0 sawMoreData=0
```

```text
ConnectSentry: rule response parse failed responseBytes=800000 chunks=13 sawMoreData=1
```

## 失败语义

### 规则 wire payload 超过 2MB

行为：

- HostGuard 侧不应发送截断内容。
- DLL 侧即使收到超过 2MB 的流，也必须拒绝。
- DLL 不进入 JSON 解析。
- DLL 不替换当前规则 snapshot。

### 读取中途失败

行为：

- DLL 返回规则拉取失败。
- 清空临时响应。
- 不解析部分内容。
- 不替换当前规则 snapshot。

### JSON 解析失败

行为：

- 记录 `responseBytes`、`chunks`、`sawMoreData`。
- 不打印 JSON。
- 不替换当前规则 snapshot。

### 启动失败与 fail-open

如果启动阶段规则拉取失败或解析失败，现有语义会进入规则不可用状态，检测侧表现为 pass-through / fail-open。

这是本方案引入 2MB wire 上限后可能触发的新降级路径：

```text
规则 wire payload 超过 2MB
    ↓
ConnectSentry 失败
    ↓
ParseAndSwap 不执行
    ↓
规则未就绪或保持旧规则
    ↓
启动场景可能 fail-open/pass-through
```

该语义需要产品和安全侧确认接受。

### reload 失败语义

当前代码已具备 reload 失败不替换旧规则的语义。

依据：

```cpp
bool loaded = connected && ParseAndSwap(json, lib);
```

以及 retry 路径中 `ConnectSentry(...)` 失败会继续等待下一轮，不会调用 `ParseAndSwap()`。

因此：

- reload 拉取失败不会清空旧 snapshot。
- reload 解析失败不会替换旧 snapshot。
- 本方案不需要额外修改该语义。

## 测试方案

### Spike 测试：2MB wire payload pipe 行为

构造 2MB wire payload。

分组：

```text
Group A: outBufferBytes = 512KB, wire payload = 2MB
Group B: outBufferBytes = 2MB,   wire payload = 2MB
Group E: client connects but does not send request
Group F: client sends request but does not read response
Group G: client reads very slowly
```

预期：

- 至少 Group A 或 Group B 能稳定写入并读取完整 2MB。
- 如果 Group A 通过，则不提升服务端 out buffer。
- 如果 Group A 失败且 Group B 通过，则提升服务端 out buffer 到 2MB。
- 如果 Group B 失败，则当前方案不成立。
- 慢客户端测试用于判断是否需要服务端写超时并入同批实现。

### 测试 1：小规则包兼容

规则响应小于 512KB。

预期：

- HostGuard 正常下发。
- DLL 正常读取。
- `chunks >= 1`。
- 规则加载成功。
- 行为与修改前一致。

### 测试 2：600KB wire payload

构造 600KB 左右 wire payload。

预期：

- HostGuard 写入成功。
- DLL 分多次 chunk 读取。
- `responseBytes > 524288`。
- JSON 解析成功。
- 规则加载成功。

### 测试 3：接近 2MB wire payload

构造以下两组：

```text
wire = 2MB - 1, JSON = 2MB - 2
wire = 2MB,     JSON = 2MB - 1
```

预期：

- HostGuard 写入成功。
- DLL 读取成功。
- 规则加载成功。
- 无截断。

### 测试 4：超过 2MB wire payload

构造：

```text
wire = 2MB + 1, JSON = 2MB
```

预期：

- HostGuard 侧拒绝或 DLL 侧拒绝。
- DLL 日志出现 `rule response too large` 或 HostGuard 日志出现 `rule response too large`。
- 不进入 JSON 解析。
- 不替换旧规则。

### 测试 5：非法 JSON

构造小于 2MB wire payload，但 JSON 不完整或格式错误的响应。

预期：

- DLL 读取完整。
- JSON 解析失败。
- 日志包含 `responseBytes`、`chunks`、`sawMoreData`。
- 不打印 JSON 内容。

### 测试 6：per-read 超时

用测试 server 接收连接后不写数据，或延迟超过 `kSentryPipeReadTimeoutMs` 再写。

预期：

- DLL 单次 read 超时后失败。
- 日志出现 `per-read timeout`。
- 不误标为 total timeout。

### 测试 7：total timeout

用测试 server 以极慢速度分批写入，每个 chunk 不超过 per-read timeout，但累计超过 `kRuleResponseTotalReadTimeoutMs`。

预期：

- DLL 在全局 10 秒截止后失败。
- 日志出现 `total timeout`。
- 不解析 partial response。

## 开发步骤

### Step 0：先做 spike

新增测试或临时测试代码，验证：

- 512KB out buffer + 2MB wire payload。
- 2MB out buffer + 2MB wire payload。
- 64KB chunk 读取。
- `ERROR_MORE_DATA` partial bytes 不丢失。
- 慢客户端对 rule pipe worker 的影响。

spike 通过后再继续正式实现。

### Step 1：确认 HostGuard out buffer 决策

根据 spike 结果决定：

```text
Group A 通过：保持 kRulePipeOutBufferBytes = 512 * 1024
Group A 失败、Group B 通过：改为 kRulePipeOutBufferBytes = 2 * 1024 * 1024
Group B 失败：停止当前方案，改协议级方案
```

如果需要提升 out buffer，先核对：

- `rulePipeThreads` 默认值。
- `rulePipeThreads` 最大值。
- `rulePipeThreads × 2MB` 内核缓冲风险是否可接受。
- `rulePipeThreads` 能否吸收少量客户端卡住 10s 而不饿死其他规则拉取。

### Step 2：新增 HostGuard 写入前 wire 长度检查

必须同时修改：

```text
src/amsi_ipc_host/src/amsi_rule_channel.cpp
src/module_amsi_detect/amsi_ipc_host/src/AmsiRuleChannel.cpp
```

新增：

```cpp
constexpr size_t kMaxRuleWireBytes = 2 * 1024 * 1024;
```

并在构造 wire 后、写入前检查：

```cpp
std::string wire = response.json + "\n";
if (wire.size() > kMaxRuleWireBytes) {
    // log length only, do not write truncated content
    return;
}
```

### Step 3：新增 DLL 专用循环读取 helper

文件：

```text
src/rasp_rule_engine/src/rasp_sentry_base.cpp
```

新增：

- `kMaxRuleWireBytes`
- `kRuleResponseReadChunkBytes`
- `kRuleResponseTotalReadTimeoutMs`
- `PipeMessageReadStats`
- `ReadOneChunkResult`
- `ReadOnePipeChunk`
- `ReadMessagePipeWithLimit`

注意：

- 不要直接复用现有 `ReadPipeWithTimeout()`。
- `ERROR_MORE_DATA` 不允许映射成 `WAIT_TIMEOUT`。
- `ERROR_MORE_DATA` 时必须 append partial bytes。
- 全局截止时间使用 `GetTickCount64()`。
- timeout 分类要区分 `perReadTimeout` 和 `totalTimeout`。

### Step 4：替换 `ConnectSentry()` 读取逻辑

文件：

```text
src/rasp_rule_engine/src/rasp_sentry_base.cpp
```

将固定 512KB 单次读取替换为循环读取。

### Step 5：补充测试

优先补充 pipe/rule channel 相关测试：

```text
src/amsi_ipc_host/tests
src/rasp_mod_amsi/tests
```

至少覆盖：

- 2MB spike。
- 慢客户端 worker 占用。
- 600KB wire payload 可读取。
- `wire = 2MB` 边界允许。
- `wire = 2MB + 1` 响应拒绝。
- per-read timeout。
- total timeout。

### Step 6：验证

执行构建：

```powershell
cmake --build D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex --target engine_runtime_tests --config Release
```

执行测试：

```powershell
D:\Code\rasp\DetectPsByAmsiCodex\src\rasp_mod_amsi\build-codex\Release\engine_runtime_tests.exe
```

如新增或已有 IPC 测试 target，也需要执行对应 target。

## 验收标准

1. spike 证明 2MB wire payload 可完整写入和读取。
2. 小于 512KB 的现有规则包行为不变。
3. 大于 512KB 且小于等于 2MB wire payload 的规则包可以成功下发和加载。
4. 超过 2MB wire payload 的规则包被明确拒绝。
5. DLL 不会解析截断响应。
6. `ERROR_MORE_DATA` chunk 不丢失。
7. `ReadOnePipeChunk` 正确处理 pending completion 后的 `ERROR_MORE_DATA + transferred > 0`。
8. 读取总耗时受全局截止时间限制。
9. timeout 日志能区分 per-read timeout 和 total timeout。
10. 失败日志可定位原因，但不泄漏规则内容。
11. 两份 `AmsiRuleChannel` 都具备 wire 长度检查。
12. 不改变 `GET_ALL_RULES\n` 协议。

## 后续演进

如果后续允许进一步优化协议，建议按以下方向演进：

1. 规则响应增加长度头。
2. 支持 `GET_RULES_HASH`。
3. hash 一致时跳过规则拉取。
4. 按模块拉取规则，例如 AMSI DLL 只拉 `AmsiProvider` 规则。
5. 支持 delta 更新。
6. 将最大规则包大小做成内部配置项，而不是客户可见策略项。
7. 服务端 rule channel 的请求读、响应写和 flush 全面改成 overlapped + timeout。

## 实现收敛补充：超限日志与边界测试

本轮实现对评审反馈做如下收敛：

1. `AmsiRuleChannel` 层不直接依赖 `rasp_sentry_native` 的 `SentryLog_*`，避免 `amsi_ipc_host -> rasp_sentry_native` 反向依赖。
2. 两份 channel 均新增最小日志回调：
   - `src/amsi_ipc_host/src/amsi_rule_channel.cpp`
   - `src/module_amsi_detect/amsi_ipc_host/src/AmsiRuleChannel.cpp`
3. 服务端 wire 超限拒绝前会通过回调输出：

```text
rule response too large wireBytes=<actual> limit=2097152
```

日志只包含长度和上限，不输出规则内容。

4. `amsi_rule_channel_tests` 补充 wire 边界：
   - `wire = 2MB - 1`：允许。
   - `wire = 2MB`：允许。
   - `wire = 2MB + 1`：拒绝，并验证出现 `rule response too large` 日志。

5. DLL 侧补充读取上限回归覆盖：
   - 通过测试钩子复用生产 `ReadMessagePipeWithLimit`。
   - 构造独立 message pipe，写入 `2MB + 1` wire payload。
   - 断言读取返回失败、`tooLarge=true`、响应内容被清空、累计读取字节数超过 2MB。

6. `rule_pipe_large_message_spike_tests` 增加注释，要求 spike reader 与 `rasp_sentry_base.cpp` 中的 `ReadOnePipeChunk` / `ReadMessagePipeWithLimit` 保持一致，避免后续逻辑漂移。
