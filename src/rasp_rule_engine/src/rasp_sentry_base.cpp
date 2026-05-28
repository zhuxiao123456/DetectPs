// =========================================================================
// rasp_sentry_base.cpp - Shared RASP infrastructure (log, IPC, threads).
//
// Extracted verbatim from iis7_rule_engine.cpp and amsi_rule_engine.cpp.
// Contains all code that was duplicated between the two modules:
//   - Ring-buffer diagnostic log + INIT_ONCE init + Log()
//   - Base64Decode
//   - ConnectSentry() IPC handshake (GET_ALL_RULES)
//   - ParseRulesJson()  (base-field recursive-descent parser)
//   - SendDetectionEvent() (replaces amsi_event_sender::SendAmsiEvent)
//   - LogForwardThreadProc  (ring-buffer drain -> amsi_detect_events)
//   - ConfigPipeThreadProc  (reload signal server on amsi_detect_config)
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
#include "../include/legacy_diag_json_builder.h"
#include "../include/legacy_diag_log_forwarder.h"
#include "../include/legacy_diag_pipe_writer.h"
#include "../include/legacy_pipe_event_transport.h"

// =========================================================================
// 处理所有与 rasp_sentry（外部守护进程）�?IPC 通信、无锁环形日志队列、以及极轻量级的 JSON 解析
// =========================================================================
static INIT_ONCE s_logCsOnce = INIT_ONCE_STATIC_INIT;
static std::atomic<long> s_hostLivenessThreads{0};

static bool BuildCurrentUserConfigPipeSecurityAttributes(SECURITY_ATTRIBUTES& sa,
                                                         PSECURITY_DESCRIPTOR& sd,
                                                         std::wstring& sddlOut)
{
    sa = { sizeof(sa), nullptr, FALSE };
    sd = nullptr;

    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
        return false;

    DWORD bytes = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &bytes);
    if (bytes == 0)
    {
        CloseHandle(token);
        return false;
    }

    std::vector<BYTE> tokenBuffer(bytes);
    if (!GetTokenInformation(token, TokenUser, tokenBuffer.data(), bytes, &bytes))
    {
        CloseHandle(token);
        return false;
    }
    CloseHandle(token);

    auto* tokenUser = reinterpret_cast<TOKEN_USER*>(tokenBuffer.data());
    LPWSTR userSid = nullptr;
    if (!ConvertSidToStringSidW(tokenUser->User.Sid, &userSid))
        return false;

    sddlOut = L"D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;";
    sddlOut += userSid;
    sddlOut += L")";
    LocalFree(userSid);

    if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddlOut.c_str(), SDDL_REVISION_1, &sd, nullptr))
        return false;

    sa.lpSecurityDescriptor = sd;
    return true;
}


bool RaspSentryBase::AnyHostLivenessThreadRunning()
{
    return s_hostLivenessThreads.load(std::memory_order_acquire) > 0;
}

void RaspSentryBase::MarkHostAlive(bool alive)
{
    m_hostAlive.store(alive, std::memory_order_release);
}

void RaspSentryBase::MarkRuleSnapshotReady(bool ready)
{
    m_ruleSnapshotReady.store(ready, std::memory_order_release);
}

void RaspSentryBase::MarkDetectionPausedByHostState(bool paused)
{
    m_hostDetectionPaused.store(paused, std::memory_order_release);
}

bool RaspSentryBase::IsHostAlive() const
{
    return m_hostAlive.load(std::memory_order_acquire);
}

bool RaspSentryBase::IsRuleSnapshotReady() const
{
    return m_ruleSnapshotReady.load(std::memory_order_acquire);
}

bool RaspSentryBase::ShouldBypassScanFast() const
{
    if (!m_running.load(std::memory_order_acquire))
        return true;
    if (m_hostDetectionPaused.load(std::memory_order_acquire))
        return true;
    if (!m_hostAlive.load(std::memory_order_acquire))
        return true;
    if (!m_ruleSnapshotReady.load(std::memory_order_acquire))
        return true;
    return false;
}

bool RaspSentryBase::ProbeRulePipe() const
{
    return WaitNamedPipeW(L"\\\\.\\pipe\\amsi_detect_rules", m_probeTimeoutMs) == TRUE;
}

void RaspSentryBase::SleepHostLivenessInterruptible(DWORD sleepMs) const
{
    DWORD elapsed = 0;
    while (!m_hostLivenessStop.load(std::memory_order_acquire) && elapsed < sleepMs) {
        DWORD slice = (sleepMs - elapsed) > 100 ? 100 : (sleepMs - elapsed);
        Sleep(slice);
        elapsed += slice;
    }
}
static BOOL WINAPI LogCsInit(INIT_ONCE*, PVOID, PVOID*)
{
    // NOTE: Each RaspSentryBase instance owns its own CRITICAL_SECTION (m_logCs)
    // and HANDLE (m_logEvent) �?this INIT_ONCE is just a one-time initializer flag
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
// Log() �?public; thread-safe; writes to OutputDebugString AND ring buffer.
// =========================================================================

void RaspSentryBase::Log(const char* fmt, ...) const
{
    va_list va;
    va_start(va, fmt);
    VLogWithSeverity(RaspDiagSeverity::Info, fmt, va);
    va_end(va);
}

void RaspSentryBase::LogWithSeverity(RaspDiagSeverity severity, const char* fmt, ...) const
{
    va_list va;
    va_start(va, fmt);
    VLogWithSeverity(severity, fmt, va);
    va_end(va);
}

void RaspSentryBase::VLogWithSeverity(RaspDiagSeverity severity, const char* fmt, va_list ap) const
{
    char buf[1024];
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);

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

    // Cast away const - ring buffer mutation is logically non-observable to callers.
    const_cast<RaspSentryBase*>(this)->EnqueueLog(buf, severity);
}
/*
 * 功能：极低开销的无�?自旋锁日志记�?
 * 流程：Log 写入环形数组（如果满了就覆盖最老的�?> 触发 m_logEvent -> 后台线程 LogForwardThreadProc 醒来 ->
 * 拼装�?JSON -> 通过命名管道 \\.\pipe\amsi_detect_events 发出
 * Mark: 日志限制长度(防止恶意日志填满缓冲�?
*/
void RaspSentryBase::EnqueueLog(const char* text, RaspDiagSeverity severity)
{
    EnsureLogCsInit();
    EnterCriticalSection(&m_logCs);
    PushLogEntryLocked(text, severity);
    LeaveCriticalSection(&m_logCs);

    if (m_logEvent) SetEvent(m_logEvent);
}

void RaspSentryBase::PushLogEntryLocked(const char* text, RaspDiagSeverity severity)
{
    if (m_logCount >= kLogQueueCap)
        m_logTail = (m_logTail + 1) % kLogQueueCap;   // evict oldest
    else
        InterlockedIncrement(&m_logCount);

    int slot = (int)(m_logHead % kLogQueueCap);
    strncpy_s(m_logQueue[slot].text, sizeof(m_logQueue[slot].text), text, _TRUNCATE);
    m_logQueue[slot].severity = severity;
    m_logHead = (m_logHead + 1) % kLogQueueCap;
}

// 调用方必须已经持�?m_logCs�?
bool RaspSentryBase::PopLogEntryLocked(char* out, size_t outSize, RaspDiagSeverity& severityOut)
{
    bool hasItem = (m_logCount > 0);
    if (hasItem)
    {
        int slot = (int)(m_logTail % kLogQueueCap);
        strncpy_s(out, outSize, m_logQueue[slot].text, _TRUNCATE);
        severityOut = m_logQueue[slot].severity;
        m_logTail = (m_logTail + 1) % kLogQueueCap;
        InterlockedDecrement(&m_logCount);
    }
    return hasItem;
}

// =========================================================================
// Base64 decoder �?可以添加一个输入、输出长度限制（防止dos攻击�?
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
// ConnectSentry �?在启动时，连接命名管道，发�?GET_ALL_RULES，阻塞读取并拉取完整的安全策�?JSON
// =========================================================================

bool RaspSentryBase::ConnectSentry(std::string& jsonOut, std::string& libSourceOut)
{
    RuleBundleMetadata ignored;
    return ConnectSentry(jsonOut, libSourceOut, ignored);
}

bool RaspSentryBase::ConnectSentry(std::string& jsonOut,
                                   std::string& libSourceOut,
                                   RuleBundleMetadata& metadataOut)
{
    Log("[%s] ConnectSentry: connecting to amsi_detect_rules", ModuleName());
    metadataOut = RuleBundleMetadata{};

    if (!WaitNamedPipeW(L"\\\\.\\pipe\\amsi_detect_rules", 100))
    {
        Log("[%s] ConnectSentry: pipe not available", ModuleName());
        return false;
    }

    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\amsi_detect_rules",
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

    Log("[%s] ConnectSentry: received %lu bytes - parsing", ModuleName(), bytesRead);

    jsonOut = response;

    // Pre-extract the lib source so callers (SentryRetryThreadProc, Initialize)
    // can pass it directly to ParseAndSwap. ParseAndSwap re-parses the JSON to
    // build its typed snapshot �?the double parse is acceptable at init/reload time.
    libSourceOut.clear();
    std::vector<std::unique_ptr<RaspRuleBase>> dummy;
    ParseRulesJson(response, libSourceOut, dummy, &metadataOut);

    Log("[%s] ConnectSentry: %zu rule(s) found, lib=%zu bytes, version=%zu bytes, hash=%zu bytes",
        ModuleName(), dummy.size(), libSourceOut.size(), metadataOut.version.size(), metadataOut.hash.size());
    return true;
}

/*
 * 递归解析检查项数组
 * */
// =========================================================================
// ParseRulesJson �?base-field parser
// =========================================================================

void RaspSentryBase::ParseRuleExtension(const std::string& /*key*/,
                                        void*              parserPtr,
                                        RaspRuleBase&      /*rule*/)
{
    // Default: skip unrecognised value so the parser advances past it.
    static_cast<Parser*>(parserPtr)->skip_value();
}

/*
 * 轻量级流�?JSON 解析器、避免引入巨大的第三�?JSON �?
 * */
bool RaspSentryBase::ParseRulesJson(
    const std::string&                          json,
    std::string&                                libSourceOut,
    std::vector<std::unique_ptr<RaspRuleBase>>& rulesOut,
    RuleBundleMetadata*                         metadataOut,
    std::vector<std::string>*                   trustProcessOut)
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

    if (metadataOut) {
        metadataOut->version = result.version;
        metadataOut->hash = result.hash;
    }
    if (trustProcessOut)
        *trustProcessOut = std::move(result.trustProcessPaths);
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

static std::string ControlStatusJsonEscape(const std::string& value)
{
    std::string out;
    out.reserve(value.size() + 8);
    for (unsigned char c : value)
    {
        switch (c)
        {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20)
            {
                char esc[7];
                snprintf(esc, sizeof(esc), "\\u%04x", static_cast<unsigned>(c));
                out += esc;
            }
            else
            {
                out.push_back(static_cast<char>(c));
            }
            break;
        }
    }
    return out;
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
    input.processPid = result.processPid;
    input.processName = result.processName;
    input.processPath = result.processPath;
    input.scriptContent = result.scriptContent;
    // Batch 3: parent process fields
    input.parentPid = result.parentPid;
    input.parentProcessName = result.parentProcessName;
    input.parentProcessPath = result.parentProcessPath;

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

void RaspSentryBase::SendRuleLoadResult(bool success,
                                        int errorCode,
                                        const std::string& errorMessage) const
{
    SendRuleLoadResult(success, errorCode, errorMessage, RuleBundleMetadata{});
}

void RaspSentryBase::SendRuleLoadResult(bool success,
                                        int errorCode,
                                        const std::string& errorMessage,
                                        const RuleBundleMetadata& requestedMetadata) const
{
    const DWORD pid = GetCurrentProcessId();
    char pidBuf[32];
    snprintf(pidBuf, sizeof(pidBuf), "%lu", static_cast<unsigned long>(pid));

    const std::string pidText(pidBuf);
    const std::string dllInstanceId = std::string("amsi_detect_") + pidText;
    const size_t ruleCount = ActiveRuleCountForStatus();
    const RuleBundleMetadata activeMetadata = ActiveRuleMetadataForStatus();

    char json[2048];
    _snprintf_s(json, sizeof(json), _TRUNCATE,
                "{\"msgType\":\"RULE_LOAD_RESULT\","
                "\"module\":\"amsi_detect\","
                "\"dllInstanceId\":\"%s\","
                "\"pid\":%s,"
                "\"timestamp\":\"%s\","
                "\"requestedVersion\":\"%s\","
                "\"requestedHash\":\"%s\","
                "\"activeVersion\":\"%s\","
                "\"activeHash\":\"%s\","
                "\"success\":%s,"
                "\"ruleCount\":%zu,"
                "\"errorCode\":%d,"
                "\"errorMessage\":\"%s\"}",
                ControlStatusJsonEscape(dllInstanceId).c_str(),
                pidText.c_str(),
                ControlStatusJsonEscape(SentryUtcTimestamp()).c_str(),
                ControlStatusJsonEscape(requestedMetadata.version).c_str(),
                ControlStatusJsonEscape(requestedMetadata.hash).c_str(),
                ControlStatusJsonEscape(activeMetadata.version).c_str(),
                ControlStatusJsonEscape(activeMetadata.hash).c_str(),
                success ? "true" : "false",
                ruleCount,
                errorCode,
                ControlStatusJsonEscape(errorMessage).c_str());

    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\amsi_detect_control_status",
                               GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        Log("[%s] SendRuleLoadResult: control status pipe unavailable GLE=%lu",
            ModuleName(), GetLastError());
        return;
    }

    DWORD written = 0;
    const DWORD expected = static_cast<DWORD>(strlen(json));
    if (!WriteFile(hPipe, json, expected, &written, nullptr) || written != expected)
    {
        Log("[%s] SendRuleLoadResult: WriteFile failed GLE=%lu written=%lu expected=%lu",
            ModuleName(), GetLastError(), written, expected);
    }
    CloseHandle(hPipe);
}

void RaspSentryBase::SetActiveRuleMetadataForStatus(const RuleBundleMetadata& metadata)
{
    std::lock_guard<std::mutex> lock(m_ruleMetadataMutex);
    m_activeRuleMetadata = metadata;
}

RuleBundleMetadata RaspSentryBase::ActiveRuleMetadataForStatus() const
{
    std::lock_guard<std::mutex> lock(m_ruleMetadataMutex);
    return m_activeRuleMetadata;
}

// =========================================================================
// LogForwardThreadProc - drains ring buffer to amsi_detect_events as diag events
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
            RaspDiagSeverity entrySeverity = RaspDiagSeverity::Info;

            EnterCriticalSection(&self->m_logCs);
            bool hasItem = self->PopLogEntryLocked(entryText, sizeof(entryText), entrySeverity);
            LeaveCriticalSection(&self->m_logCs);

            if (!hasItem) break;

            LegacyDiagJsonBuildInput input;
            input.id = SentryGenerateEventId();
            input.timestamp = SentryUtcTimestamp();
            input.module = self->ModuleName();
            input.pattern = self->LogEventPattern();
            input.message = entryText;
            input.severity = entrySeverity;

            LegacyDiagJsonBuildResult built = LegacyDiagJsonBuilder().Build(input);
            const std::string& compactJson = built.compactJson;

            LegacyDiagPipeWriter writer;
            LegacyDiagLogForwarder forwarder(writer);
            forwarder.Forward(compactJson);
        }

        if (!self->m_logThreadAlive && self->m_logCount == 0)
            break;
    }

    return 0;
}

// =========================================================================
// HostLivenessThreadProc - fail-open when Host/rule pipe disappears.
// =========================================================================

DWORD WINAPI RaspSentryBase::HostLivenessThreadProc(LPVOID param)
{
    auto* self = static_cast<RaspSentryBase*>(param);
    self->m_hostLivenessRunning.store(true, std::memory_order_release);
    s_hostLivenessThreads.fetch_add(1, std::memory_order_acq_rel);

    DWORD consecutiveFailures = 0;
    DWORD firstFailureTick = 0;
    bool graceLogged = false;
    bool lostLogged = false;

    while (!self->m_hostLivenessStop.load(std::memory_order_acquire) &&
           self->m_running.load(std::memory_order_acquire)) {
        const bool ok = self->ProbeRulePipe();
        const DWORD now = GetTickCount();

        if (ok) {
            consecutiveFailures = 0;
            firstFailureTick = 0;
            graceLogged = false;
            lostLogged = false;

            const bool wasAlive = self->m_hostAlive.exchange(true, std::memory_order_acq_rel);
            if (!wasAlive) {
                self->Log("[%s] Host rule pipe visible again, waiting reload/resume before detection resumes",
                          self->ModuleName());
            }

            self->SleepHostLivenessInterruptible(self->m_probeIntervalMs);
            continue;
        }

        if (consecutiveFailures == 0) {
            firstFailureTick = now;
            if (!graceLogged) {
                self->LogWithSeverity(RaspDiagSeverity::Debug,
                                      "[%s] Host liveness probe failed, entering grace period",
                                      self->ModuleName());
                graceLogged = true;
            }
        }

        ++consecutiveFailures;
        const bool exceededFailures = consecutiveFailures >= self->m_maxConsecutiveFailures;
        const bool exceededGrace = firstFailureTick != 0 &&
                                   static_cast<DWORD>(now - firstFailureTick) >= self->m_hostLostGraceMs;

        if (exceededFailures && exceededGrace) {
            self->m_hostAlive.store(false, std::memory_order_release);
            self->m_hostDetectionPaused.store(true, std::memory_order_release);
            self->m_ruleSnapshotReady.store(false, std::memory_order_release);

            if (!lostLogged) {
                self->LogWithSeverity(RaspDiagSeverity::Warning,
                                      "[%s] Host liveness lost, pause AMSI detection until host reload/resume",
                                      self->ModuleName());
                lostLogged = true;
            }
        }

        self->SleepHostLivenessInterruptible(self->m_probeIntervalMs);
    }

    s_hostLivenessThreads.fetch_sub(1, std::memory_order_acq_rel);
    self->m_hostLivenessRunning.store(false, std::memory_order_release);
    return 0;
}
// =========================================================================
// ConfigPipeThreadProc - server on \\.\pipe\amsi_detect_config
// Dark period of 600ms after handling prevents BroadcastReload reconnect loop.
// (See AMSI ConfigPipeThread comments for full explanation.)
// =========================================================================

DWORD WINAPI RaspSentryBase::ConfigPipeThreadProc(LPVOID param)
{
    auto* self = static_cast<RaspSentryBase*>(param);

    self->Log("[%s] ConfigPipeThread: started", self->ModuleName());

    SECURITY_DESCRIPTOR sd = {};
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE); // NULL DACL = allow all.

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    auto CreateConfigPipe = [&sa]() -> HANDLE {
        return CreateNamedPipeW(
            L"\\\\.\\pipe\\amsi_detect_config",
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            0, 1, 0, &sa);
    };

    while (self->m_running.load()) {
        HANDLE hPipe = CreateConfigPipe();
        if (hPipe == INVALID_HANDLE_VALUE) {
            self->LogWithSeverity(RaspDiagSeverity::Warning,
                                  "[%s] ConfigPipeThread: CreateNamedPipeW failed GLE=%lu - retrying in 1s",
                                  self->ModuleName(), GetLastError());
            Sleep(1000);
            continue;
        }

        BOOL connected = ConnectNamedPipe(hPipe, nullptr);
        DWORD connectErr = connected ? 0 : GetLastError();
        if (!self->m_running.load())
        {
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            break;
        }
        if (!connected && connectErr != ERROR_PIPE_CONNECTED)
        {
            self->Log("[%s] ConfigPipeThread: ConnectNamedPipe failed GLE=%lu",
                      self->ModuleName(), connectErr);
            CloseHandle(hPipe);
            continue;
        }

        BYTE signal = 0;
        DWORD readBytes = 0;
        ReadFile(hPipe, &signal, 1, &readBytes, nullptr);
        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);

        self->Log("[%s] ConfigPipeThread: signal=0x%02X (readBytes=%lu)",
                  self->ModuleName(), static_cast<unsigned>(signal), readBytes);

        if (signal == 0x01 && self->m_running.load()) {
            self->Log("[%s] ConfigPipeThread: reload signal - pulling updated rules",
                      self->ModuleName());
            self->OnReloadSignal();

            if (self->m_running.load())
                Sleep(600);
        } else if (signal == 0x02) {
            self->Log("[%s] ConfigPipeThread: unload signal - calling OnUnloadSignal()",
                      self->ModuleName());
            self->OnUnloadSignal();
        } else if (signal == 0x03) {
            self->Log("[%s] ConfigPipeThread: pause detection signal - disabling scan entry",
                      self->ModuleName());
            self->OnPauseDetectionSignal();
        } else if (signal == 0x04) {
            self->Log("[%s] ConfigPipeThread: resume detection signal - enabling scan entry",
                      self->ModuleName());
            self->OnResumeDetectionSignal();
        }
    }
    self->Log("[%s] ConfigPipeThread: exiting", self->ModuleName());
    return 0;
}
// =========================================================================
// SentryRetryThreadProc - polls ConnectSentry+ParseAndSwap every 5 s.
// Exits after first successful load. Enabled unconditionally for all modules
// (AMSI processes can start before rasp_sentry and would never receive a
// reload signal because they were not alive when sentry broadcast it).
// =========================================================================

DWORD WINAPI RaspSentryBase::SentryRetryThreadProc(LPVOID param)
{
    auto* self = static_cast<RaspSentryBase*>(param);
    self->Log("[%s] SentryRetryThread: started - polling every 5s", self->ModuleName());

    while (self->m_running.load())
    {
        // 5 s in 100 ms slices so Shutdown() wakes us promptly
        for (int i = 0; i < 50 && self->m_running.load(); i++)
            Sleep(100);

        if (!self->m_running.load()) break;

        std::string json;
        std::string lib;
        RuleBundleMetadata requestedMetadata;
        if (self->ConnectSentry(json, lib, requestedMetadata) && self->ParseAndSwap(json, lib)) {
            self->SetActiveRuleMetadataForStatus(requestedMetadata);
            self->MarkHostAlive(true);
            self->MarkRuleSnapshotReady(true);
            self->MarkDetectionPausedByHostState(true);
            self->Log("[%s] SentryRetryThread: rules loaded - waiting resume before detection resumes", self->ModuleName());
            self->SendRuleLoadResult(true, 0, "", requestedMetadata);
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
    m_hostLivenessStop.store(false, std::memory_order_release);
    m_hostAlive.store(false, std::memory_order_release);
    m_hostDetectionPaused.store(true, std::memory_order_release);
    m_ruleSnapshotReady.store(false, std::memory_order_release);
    EnsureLogCsInit();
    m_eventSink.Start([this](const AsyncEvent& event) {
        return SendDetectionEventSyncWorkerOnly(event);
    });

    // Wire Lua print() to this engine's Log so dbg() in rule scripts routes
    // through the ring buffer and appears in DebugView + amsi_detect_events.
    // Use a lambda that captures 'this'; stored in a static to give it a
    // function-pointer-compatible type via a module-global trampoline approach.
    // Because each module has exactly one engine instance, a module-scope
    // RaspLog free function calls g_engine.Log() / g_engine->Log(), so we
    // wire that module-level free function via SetLogFn in each derived class's
    // Initialize() override if needed. Here we set a default no-op proxy that
    // derived classes replace in their own Initialize before calling base.
    // (IIS7 and AMSI both set the proxy before calling base Initialize via
    //  the existing pattern �?see their OnBeginInit hooks.)

    Log("[%s] Initialize: starting - all config via rasp_sentry IPC", ModuleName());

    std::string json, lib;
    RuleBundleMetadata requestedMetadata;
    bool connected = ConnectSentry(json, lib, requestedMetadata);
    bool loaded = connected && ParseAndSwap(json, lib);

    if (loaded)
    {
        SetActiveRuleMetadataForStatus(requestedMetadata);
        MarkHostAlive(true);
        MarkRuleSnapshotReady(true);
        MarkDetectionPausedByHostState(false);
        Log("[%s] Initialize: rules loaded from sentry", ModuleName());
        SendRuleLoadResult(true, 0, "", requestedMetadata);
    }
    else
    {
        MarkHostAlive(false);
        MarkRuleSnapshotReady(false);
        MarkDetectionPausedByHostState(true);
        SendRuleLoadResult(false,
                           connected ? 3 : 1,
                           connected ? "initial rule load failed" : "rules pipe unavailable",
                           requestedMetadata);
        Log("[%s] Initialize: sentry unavailable - pass-through; starting retry thread",
            ModuleName());
        m_retryThread = CreateThread(nullptr, 0, SentryRetryThreadProc, this, 0, nullptr);
    }

    m_configThread = CreateThread(nullptr, 0, ConfigPipeThreadProc, this, 0, nullptr);
    m_hostLivenessThread = CreateThread(nullptr, 0, HostLivenessThreadProc, this, 0, nullptr);
    if (m_hostLivenessThread == INVALID_HANDLE_VALUE || m_hostLivenessThread == nullptr) {
        MarkHostAlive(false);
        MarkRuleSnapshotReady(false);
        MarkDetectionPausedByHostState(true);
        LogWithSeverity(RaspDiagSeverity::Warning,
                        "[%s] Initialize: failed to start host liveness watcher GLE=%lu - detection paused",
                        ModuleName(), GetLastError());
        m_hostLivenessThread = INVALID_HANDLE_VALUE;
    }
    m_logThread    = CreateThread(nullptr, 0, LogForwardThreadProc,  this, 0, nullptr);

    Log("[%s] Initialize: ConfigPipeThread + HostLivenessThread + LogForwardThread started", ModuleName());
}

void RaspSentryBase::Shutdown()
{
    m_running.store(false, std::memory_order_release);
    m_hostLivenessStop.store(true, std::memory_order_release);
    m_hostDetectionPaused.store(true, std::memory_order_release);
    m_ruleSnapshotReady.store(false, std::memory_order_release);
    m_eventSink.Stop(std::chrono::milliseconds(1000));

    // 1. Stop host liveness watcher before draining logs so its final messages flush.
    if (m_hostLivenessThread != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(m_hostLivenessThread, 3000);
        CloseHandle(m_hostLivenessThread);
        m_hostLivenessThread = INVALID_HANDLE_VALUE;
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
        HANDLE hDummy = CreateFileW(L"\\\\.\\pipe\\amsi_detect_config",
                                    GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hDummy != INVALID_HANDLE_VALUE) CloseHandle(hDummy);

        WaitForSingleObject(m_configThread, 2000);
        CloseHandle(m_configThread);
        m_configThread = INVALID_HANDLE_VALUE;
    }

    // 4. Drain log thread last (final flush after other background threads stop)
    m_logThreadAlive = false;
    if (m_logEvent) SetEvent(m_logEvent);
    if (m_logThread != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(m_logThread, 3000);
        CloseHandle(m_logThread);
        m_logThread = INVALID_HANDLE_VALUE;
    }
}
