// =========================================================================
// rasp_sentry_base.cpp — Shared RASP infrastructure (log, IPC, threads).
//
// Extracted verbatim from iis7_rule_engine.cpp and amsi_rule_engine.cpp.
// Contains all code that was duplicated between the two modules:
//   - Ring-buffer diagnostic log + INIT_ONCE init + Log()
//   - Base64Decode
//   - ConnectSentry() IPC handshake (GET_ALL_RULES)
//   - ParseRulesJson()  (base-field recursive-descent parser)
//   - SendDetectionEvent() (replaces amsi_event_sender::SendAmsiEvent)
//   - LogForwardThreadProc  (ring-buffer drain → rasp_sentry_events)
//   - ConfigPipeThreadProc  (reload signal server on rasp_sentry_config)
//   - SentryRetryThreadProc (polls sentry every 5 s until first load)
//   - Initialize() / Shutdown()
// =========================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <sddl.h>
#include <string>
#include <vector>
#include <memory>
#include <cstdarg>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <algorithm>

#include "../include/rasp_sentry_base.h"
#include "../include/event_submit_client.h"
#include "../include/event_worker_sender.h"
#include "../include/legacy_pipe_event_transport.h"

// =========================================================================
// 处理所有与 rasp_sentry（外部守护进程）的 IPC 通信、无锁环形日志队列、以及极轻量级的 JSON 解析
// =========================================================================
static INIT_ONCE s_logCsOnce = INIT_ONCE_STATIC_INIT;

static BOOL WINAPI LogCsInit(INIT_ONCE*, PVOID, PVOID*)
{
    // NOTE: Each RaspSentryBase instance owns its own CRITICAL_SECTION (m_logCs)
    // and HANDLE (m_logEvent) — this INIT_ONCE is just a one-time initializer flag
    // per process. Actual per-instance init happens in EnsureLogCsInit().
    return TRUE;
}

void RaspSentryBase::EnsureLogCsInit()
{
    if (m_logCsReady) return;
    InitOnceExecuteOnce(&s_logCsOnce, LogCsInit, nullptr, nullptr);
    InitializeCriticalSectionAndSpinCount(&m_logCs, 1000);
    m_logEvent   = CreateEventW(nullptr, FALSE, FALSE, nullptr); // auto-reset
    m_logCsReady = true;
}

// =========================================================================
// Log() — public; thread-safe; writes to OutputDebugString AND ring buffer.
// =========================================================================

void RaspSentryBase::Log(const char* fmt, ...) const
{
    char buf[1024];
    va_list va;
    va_start(va, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);

    if (n >= (int)sizeof(buf))
    {
        static const char kTrunc[] = "...<truncated>";
        memcpy(buf + sizeof(buf) - sizeof(kTrunc), kTrunc, sizeof(kTrunc));
    }

    int len = (int)strlen(buf);
    if (len > 0 && buf[len - 1] != '\n' && len < (int)sizeof(buf) - 1)
    {
        buf[len]     = '\n';
        buf[len + 1] = '\0';
    }

    OutputDebugStringA(buf);

    // Cast away const — ring buffer mutation is logically non-observable to callers.
    const_cast<RaspSentryBase*>(this)->EnqueueLog(buf);
}
/*
 * 功能：极低开销的无锁/自旋锁日志记录
 * 流程：Log 写入环形数组（如果满了就覆盖最老的）-> 触发 m_logEvent -> 后台线程 LogForwardThreadProc 醒来 ->
 * 拼装为 JSON -> 通过命名管道 \\.\pipe\rasp_sentry_events 发出
 * Mark: 日志限制长度(防止恶意日志填满缓冲区)
*/
void RaspSentryBase::EnqueueLog(const char* text)
{
    EnsureLogCsInit();
    EnterCriticalSection(&m_logCs);
    PushLogEntryLocked(text);
    LeaveCriticalSection(&m_logCs);

    if (m_logEvent) SetEvent(m_logEvent);
}

void RaspSentryBase::PushLogEntryLocked(const char* text)
{
    if (m_logCount >= kLogQueueCap)
        m_logTail = (m_logTail + 1) % kLogQueueCap;   // evict oldest
    else
        InterlockedIncrement(&m_logCount);

    int slot = (int)(m_logHead % kLogQueueCap);
    strncpy_s(m_logQueue[slot].text, sizeof(m_logQueue[slot].text), text, _TRUNCATE);
    m_logHead = (m_logHead + 1) % kLogQueueCap;
}

// 调用方必须已经持有 m_logCs。
bool RaspSentryBase::PopLogEntryLocked(char* out, size_t outSize)
{
    bool hasItem = (m_logCount > 0);
    if (hasItem)
    {
        int slot = (int)(m_logTail % kLogQueueCap);
        strncpy_s(out, outSize, m_logQueue[slot].text, _TRUNCATE);
        m_logTail = (m_logTail + 1) % kLogQueueCap;
        InterlockedDecrement(&m_logCount);
    }
    return hasItem;
}

// =========================================================================
// Base64 decoder — 可以添加一个输入、输出长度限制（防止dos攻击）
// =========================================================================
bool RaspSentryBase::Base64Decode(const std::string& input, std::string& output)
{
    static const char kDecodeTable[256] =
    {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 0x00-0x0F
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1, // 0x10-0x1F
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63, // 0x20-0x2F (+,/)
        52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1, // 0x30-0x3F (0-9)
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, // 0x40-0x4F (A-O)
        15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1, // 0x50-0x5F (P-Z)
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40, // 0x60-0x6F (a-o)
        41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1  // 0x70-0x7F (p-z)
    };

    output.clear();
    output.reserve((input.size() / 4) * 3 + 3);

    int val = 0, valb = -8;
    for (unsigned char c : input)
    {
        if (c == '=' || c == '\r' || c == '\n' || c == ' ') continue;
        if (c > 127) return false;
        int d = kDecodeTable[(int)c];
        if (d < 0) return false;
        val  = (val << 6) + d;
        valb += 6;
        if (valb >= 0)
        {
            output += static_cast<char>((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return true;
}

// =========================================================================
// ConnectSentry — 在启动时，连接命名管道，发送 GET_ALL_RULES，阻塞读取并拉取完整的安全策略 JSON
// =========================================================================

bool RaspSentryBase::ConnectSentry(std::string& jsonOut, std::string& libSourceOut)
{
    Log("[%s] ConnectSentry: connecting to rasp_sentry_rules", ModuleName());

    if (!WaitNamedPipeW(L"\\\\.\\pipe\\rasp_sentry_rules", 100))
    {
        Log("[%s] ConnectSentry: pipe not available", ModuleName());
        return false;
    }

    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\rasp_sentry_rules",
                               GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        Log("[%s] ConnectSentry: CreateFileW failed GLE=%lu", ModuleName(), GetLastError());
        return false;
    }

    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(hPipe, &mode, nullptr, nullptr))
    {
        Log("[%s] ConnectSentry: SetNamedPipeHandleState failed GLE=%lu", ModuleName(), GetLastError());
        CloseHandle(hPipe);
        return false;
    }

    const char req[] = "GET_ALL_RULES\n";
    DWORD written = 0;
    if (!WriteFile(hPipe, req, (DWORD)strlen(req), &written, nullptr) || written == 0)
    {
        Log("[%s] ConnectSentry: WriteFile failed GLE=%lu", ModuleName(), GetLastError());
        CloseHandle(hPipe);
        return false;
    }

    std::string response;
    response.resize(524288); // 512 KB
    DWORD bytesRead = 0;
    BOOL  ok        = ReadFile(hPipe, &response[0], (DWORD)response.size(), &bytesRead, nullptr);
    DWORD readErr   = ok ? 0 : GetLastError();
    CloseHandle(hPipe);

    if (!ok || bytesRead == 0)
    {
        Log("[%s] ConnectSentry: ReadFile failed GLE=%lu bytes=%lu", ModuleName(), readErr, bytesRead);
        return false;
    }
    response.resize(bytesRead);

    Log("[%s] ConnectSentry: received %lu bytes — parsing", ModuleName(), bytesRead);

    jsonOut = response;

    // Pre-extract the lib source so callers (SentryRetryThreadProc, Initialize)
    // can pass it directly to ParseAndSwap. ParseAndSwap re-parses the JSON to
    // build its typed snapshot — the double parse is acceptable at init/reload time.
    libSourceOut.clear();
    std::vector<std::unique_ptr<RaspRuleBase>> dummy;
    ParseRulesJson(response, libSourceOut, dummy);

    Log("[%s] ConnectSentry: %zu rule(s) found, lib=%zu bytes",
        ModuleName(), dummy.size(), libSourceOut.size());
    return true;
}

/*
 * 递归解析检查项数组
 * */
// =========================================================================
// ParseRulesJson — base-field parser
// =========================================================================

void RaspSentryBase::ParseRuleExtension(const std::string& /*key*/,
                                        void*              parserPtr,
                                        RaspRuleBase&      /*rule*/)
{
    // Default: skip unrecognised value so the parser advances past it.
    static_cast<Parser*>(parserPtr)->skip_value();
}

/*
 * 轻量级流式 JSON 解析器、避免引入巨大的第三方 JSON 库
 * */
bool RaspSentryBase::ParseRulesJson(
    const std::string&                          json,
    std::string&                                libSourceOut,
    std::vector<std::unique_ptr<RaspRuleBase>>& rulesOut)
{
    class FactoryAdapter final : public IRuleObjectFactory {
    public:
        explicit FactoryAdapter(const RaspSentryBase& owner) : owner_(owner) {}
        RaspRuleBase* CreateRule() const override { return owner_.AllocRule(); }
    private:
        const RaspSentryBase& owner_;
    };

    class ExtensionAdapter final : public IRuleExtensionParser {
    public:
        explicit ExtensionAdapter(RaspSentryBase& owner) : owner_(owner) {}
        void ParseRuleExtension(const std::string& key,
                                void* parserContext,
                                RaspRuleBase& rule) override
        {
            owner_.ParseRuleExtension(key, parserContext, rule);
        }
    private:
        RaspSentryBase& owner_;
    };

    FactoryAdapter factory(*this);
    ExtensionAdapter extensionParser(*this);
    RuleJsonParser parser;
    RuleParseResult result = parser.Parse(json, factory, extensionParser);

    libSourceOut = std::move(result.libSource);
    rulesOut = std::move(result.rules);
    return result.ok;

                    // ── Base fields ──────────────────────────────────────
                    // ── Module-specific fields ────────────────────────────
}

// =========================================================================
// SendDetectionEvent - queues detection events for async worker delivery.
// JSON construction is handled by EventJsonBuilder.
// Worker-only pipe writes are handled by LegacyPipeEventTransport.
// Diag log forwarding remains on the legacy path until B0-3-3.
// =========================================================================

namespace {

static std::string SentryGenerateEventId()
{
    LARGE_INTEGER t;
    QueryPerformanceCounter(&t);
    char buf[17];
    snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)t.QuadPart);
    return std::string(buf);
}

static std::string SentryUtcTimestamp()
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    char buf[32];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return std::string(buf);
}

} // anonymous namespace
/*
 * Detection events are converted to AsyncEvent and queued for the async worker.
 * Worker-only pipe writes are handled by LegacyPipeEventTransport.
 * Diag log forwarding remains on the legacy path until B0-3-3.
 */
void RaspSentryBase::SendDetectionEvent(const RaspEvalResult& result) const
{
    TrySubmitDetectionEvent(result);
}

EnqueueResult RaspSentryBase::TrySubmitDetectionEvent(const RaspEvalResult& result) const
{
    EventJsonBuildInput input;
    input.eventId = SentryGenerateEventId();
    input.timestamp = SentryUtcTimestamp();
    input.moduleName = ModuleName();
    input.ruleId = result.ruleId;
    input.sensor = result.sensor;
    input.block = result.block;
    input.severity = result.severity;
    input.description = result.desc;
    input.appName = result.appName;
    input.contentName = result.contentName;
    input.confidence = result.confidence;
    input.ip = result.ip;
    input.ua = result.ua;
    input.payload = result.payload;

    EventJsonBuildResult built = EventJsonBuilder().BuildDetection(input);

    AsyncEvent event;
    event.priority = EventPriority::Detection;
    event.type = EventType::Detection;
    event.pid = GetCurrentProcessId();
    event.tid = GetCurrentThreadId();
    event.ruleId = result.ruleId;
    event.decision = built.decision;
    event.contentName = result.contentName;
    event.appName = result.appName;
    event.sampleLen = result.payload.size();
    event.reason = result.desc;
    event.eventTruncated = built.eventTruncated;
    event.compactJson = built.compactJson;
    return m_eventSink.TrySubmit(event);
}

bool RaspSentryBase::SendDetectionEventSyncWorkerOnly(const AsyncEvent& event) const
{
    // Worker-only. Must never be called from Scan hot path.
    LegacyPipeEventTransport transport;
    return SendAsyncEventWorkerOnly(event, transport, 0);
}

// =========================================================================
// LogForwardThreadProc — drains ring buffer to rasp_sentry_events as diag events
// =========================================================================

DWORD WINAPI RaspSentryBase::LogForwardThreadProc(LPVOID param)
{
    auto* self = static_cast<RaspSentryBase*>(param);
    self->m_logThreadAlive = true;

    for (;;)
    {
        WaitForSingleObject(self->m_logEvent, 500);

        for (;;)
        {
            char entryText[1024] = {};

            EnterCriticalSection(&self->m_logCs);
            bool hasItem = self->PopLogEntryLocked(entryText, sizeof(entryText));
            LeaveCriticalSection(&self->m_logCs);

            if (!hasItem) break;

            // Build JSONL diagnostic event (cat=diag)
            std::string desc;
            desc.reserve(strlen(entryText) + 4);
            for (const char* cp = entryText; *cp; ++cp)
            {
                switch (*cp)
                {
                case '"':  desc += "\\\""; break;
                case '\\': desc += "\\\\"; break;
                case '\n': desc += "\\n";  break;
                case '\r': desc += "\\r";  break;
                case '\t': desc += "\\t";  break;
                default:
                    if ((unsigned char)*cp < 0x20)
                    {
                        char esc[8];
                        snprintf(esc, sizeof(esc), "\\u%04x", (unsigned char)*cp);
                        desc += esc;
                    }
                    else desc += *cp;
                    break;
                }
            }

            std::string id = SentryGenerateEventId();
            std::string ts = SentryUtcTimestamp();

            char line[2048];
            snprintf(line, sizeof(line),
                     "{\"id\":\"%s\",\"ts\":\"%s\","
                     "\"sev\":\"info\",\"act\":\"audit\",\"cat\":\"diag\","
                     "\"mod\":\"%s\",\"sensor\":\"RaspLog\","
                     "\"rule\":\"\",\"desc\":\"%s\","
                     "\"method\":\"\",\"url\":\"\",\"ip\":\"\",\"ua\":\"\","
                     "\"pattern\":\"%s\",\"payload\":\"\"}",
                     id.c_str(), ts.c_str(),
                     self->ModuleName(),
                     desc.c_str(),
                     self->LogEventPattern());

            HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\rasp_sentry_events",
                                       GENERIC_WRITE, 0, nullptr,
                                       OPEN_EXISTING, 0, nullptr);
            if (hPipe != INVALID_HANDLE_VALUE)
            {
                DWORD written = 0;
                WriteFile(hPipe, line, (DWORD)strlen(line), &written, nullptr);
                CloseHandle(hPipe);
            }
        }

        if (!self->m_logThreadAlive && self->m_logCount == 0)
            break;
    }

    return 0;
}

// =========================================================================
// ConfigPipeThreadProc — server on \\.\pipe\rasp_sentry_config
// Dark period of 600ms after handling prevents BroadcastReload reconnect loop.
// (See AMSI ConfigPipeThread comments for full explanation.)
// =========================================================================

DWORD WINAPI RaspSentryBase::ConfigPipeThreadProc(LPVOID param)
{
    auto* self = static_cast<RaspSentryBase*>(param);

    self->Log("[%s] ConfigPipeThread: started", self->ModuleName());

    // **任何人（哪怕是 Guest 权限的恶意进程）**都可以连接你的 \\.\pipe\rasp_sentry_config 管道，并向里面发送 0x01 (重新加载) 或 0x02 (卸载) 指令。
    // 攻击者可以疯狂向这个管道发送 0x01 触发引擎无限重载，导致服务器 CPU 100%
    // 建议: 绝不能用 NULL DACL。必须通过 SDDL 字符串（如 D:(A;;GA;;;SY)(A;;GA;;;BA)）严格限制，只有 SYSTEM 权限和 Local Administrators 才能访问该管道
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, FALSE };
    LPCWSTR sddl = L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;CO)";
    // SY: SYSTEM
    // BA: Built-in Administrators
    // CO: Creator Owner (确保进程自己永远能连接自己创建的管道，防止 Shutdown 唤醒失败)
    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl, SDDL_REVISION_1, &sa.lpSecurityDescriptor, nullptr)) {
        self->Log("[%s] ConfigPipeThread: Fatal - failed to create secure SD", self->ModuleName());
        return 0;  // 权限创建失败，拒绝裸奔，直接退出
    }
    auto CreateConfigPipe = [&sa]() -> HANDLE {
        return CreateNamedPipeW(
            L"\\\\.\\pipe\\rasp_sentry_config",
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            0, 1, 0, &sa);  // 传入受限的安全属性
    };

    while (self->m_running.load()) {
        HANDLE hPipe = CreateConfigPipe();
        if (hPipe == INVALID_HANDLE_VALUE) {
            self->Log("[%s] ConfigPipeThread: CreateNamedPipeW failed GLE=%lu — retrying in 1s",
                      self->ModuleName(), GetLastError());
            Sleep(1000);
            continue;
        }
        // 同步阻塞：等待客户端连接 (注: Shutdown() 中需要有一个 Dummy 连接来唤醒此处)
        BOOL  connected   = ConnectNamedPipe(hPipe, nullptr);
        DWORD connectErr  = connected ? 0 : GetLastError();
        // 唤醒后立刻检查是否在关机
        if (!self->m_running.load())
        {
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            break;
        }
        // 处理假连接或错误
        if (!connected && connectErr != ERROR_PIPE_CONNECTED)
        {
            self->Log("[%s] ConfigPipeThread: ConnectNamedPipe failed GLE=%lu",
                      self->ModuleName(), connectErr);
            CloseHandle(hPipe);
            continue;
        }

        BYTE  signal    = 0;
        DWORD readBytes = 0;
        // 读取指令字节
        ReadFile(hPipe, &signal, 1, &readBytes, nullptr);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);

        self->Log("[%s] ConfigPipeThread: signal=0x%02X (readBytes=%lu)",
                  self->ModuleName(), (unsigned)signal, readBytes);

        if (signal == 0x01 && self->m_running.load()) {
            self->Log("[%s] ConfigPipeThread: reload signal — pulling updated rules",
                      self->ModuleName());
            self->OnReloadSignal();

            // Dark period: must exceed BroadcastReload's Connect timeout (500ms)
            if (self->m_running.load())
                Sleep(600);
        } else if (signal == 0x02) {
            self->Log("[%s] ConfigPipeThread: unload signal — calling OnUnloadSignal()",
                      self->ModuleName());
            self->OnUnloadSignal();
            // OnUnloadSignal() spawns an unload thread that calls Shutdown()
            // (sets m_running=false). Loop exits on next iteration check.
        }
    }
    LocalFree(sa.lpSecurityDescriptor);  // 申请内存必须释放
    self->Log("[%s] ConfigPipeThread: exiting", self->ModuleName());
    return 0;
}

// =========================================================================
// SentryRetryThreadProc — polls ConnectSentry+ParseAndSwap every 5 s.
// Exits after first successful load. Enabled unconditionally for all modules
// (AMSI processes can start before rasp_sentry and would never receive a
// reload signal because they were not alive when sentry broadcast it).
// =========================================================================

DWORD WINAPI RaspSentryBase::SentryRetryThreadProc(LPVOID param)
{
    auto* self = static_cast<RaspSentryBase*>(param);
    self->Log("[%s] SentryRetryThread: started — polling every 5s", self->ModuleName());

    while (self->m_running.load())
    {
        // 5 s in 100 ms slices so Shutdown() wakes us promptly
        for (int i = 0; i < 50 && self->m_running.load(); i++)
            Sleep(100);

        if (!self->m_running.load()) break;

        std::string json;
        std::string lib;
        if (self->ConnectSentry(json, lib) && self->ParseAndSwap(json, lib)) {
            self->Log("[%s] SentryRetryThread: rules loaded — exiting", self->ModuleName());
            break;
        }

        self->Log("[%s] SentryRetryThread: sentry still unavailable", self->ModuleName());
    }

    self->Log("[%s] SentryRetryThread: exiting", self->ModuleName());
    return 0;
}

// =========================================================================
// Initialize / Shutdown
// =========================================================================

void RaspSentryBase::Initialize()
{
    m_running.store(true);
    EnsureLogCsInit();
    m_eventSink.Start([this](const AsyncEvent& event) {
        return SendDetectionEventSyncWorkerOnly(event);
    });

    // Wire Lua print() to this engine's Log so dbg() in rule scripts routes
    // through the ring buffer and appears in DebugView + rasp_sentry_events.
    // Use a lambda that captures 'this'; stored in a static to give it a
    // function-pointer-compatible type via a module-global trampoline approach.
    // Because each module has exactly one engine instance, a module-scope
    // RaspLog free function calls g_engine.Log() / g_engine->Log(), so we
    // wire that module-level free function via SetLogFn in each derived class's
    // Initialize() override if needed. Here we set a default no-op proxy that
    // derived classes replace in their own Initialize before calling base.
    // (IIS7 and AMSI both set the proxy before calling base Initialize via
    //  the existing pattern — see their OnBeginInit hooks.)

    Log("[%s] Initialize: starting — all config via rasp_sentry IPC", ModuleName());

    std::string json, lib;
    bool loaded = ConnectSentry(json, lib) && ParseAndSwap(json, lib);

    if (loaded)
    {
        Log("[%s] Initialize: rules loaded from sentry", ModuleName());
    }
    else
    {
        Log("[%s] Initialize: sentry unavailable — pass-through; starting retry thread",
            ModuleName());
        m_retryThread = CreateThread(nullptr, 0, SentryRetryThreadProc, this, 0, nullptr);
    }

    m_configThread = CreateThread(nullptr, 0, ConfigPipeThreadProc, this, 0, nullptr);
    m_logThread    = CreateThread(nullptr, 0, LogForwardThreadProc,  this, 0, nullptr);

    Log("[%s] Initialize: ConfigPipeThread + LogForwardThread started", ModuleName());
}

void RaspSentryBase::Shutdown()
{
    m_running.store(false);
    m_eventSink.Stop(std::chrono::milliseconds(1000));

    // 1. Drain log thread first (final flush before other threads close)
    m_logThreadAlive = false;
    if (m_logEvent) SetEvent(m_logEvent);
    if (m_logThread != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(m_logThread, 3000);
        CloseHandle(m_logThread);
        m_logThread = INVALID_HANDLE_VALUE;
    }

    // 2. Stop retry thread (exits within 100ms of m_running=false)
    if (m_retryThread != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(m_retryThread, 3000);
        CloseHandle(m_retryThread);
        m_retryThread = INVALID_HANDLE_VALUE;
    }

    // 3. Unblock ConnectNamedPipe with a dummy client, then wait
    if (m_configThread != INVALID_HANDLE_VALUE)
    {
        HANDLE hDummy = CreateFileW(L"\\\\.\\pipe\\rasp_sentry_config",
                                    GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hDummy != INVALID_HANDLE_VALUE) CloseHandle(hDummy);

        WaitForSingleObject(m_configThread, 2000);
        CloseHandle(m_configThread);
        m_configThread = INVALID_HANDLE_VALUE;
    }
}
