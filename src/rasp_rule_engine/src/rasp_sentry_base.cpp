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
//   - SentryRetryThreadProc (actively polls sentry for state/rule updates)
//   - Initialize() / Shutdown()
// =========================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <sddl.h>
#include <bcrypt.h>
#include <string>
#include <vector>
#include <memory>
#include <cstdarg>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <algorithm>
#include <cctype>

#include "../include/rasp_sentry_base.h"
#include "../include/event_submit_client.h"
#include "../include/event_worker_sender.h"
#include "../include/legacy_diag_json_builder.h"
#include "../include/legacy_diag_log_forwarder.h"
#include "../include/legacy_diag_pipe_writer.h"
#include "../include/legacy_pipe_event_transport.h"

// =========================================================================
// 处理所有与 rasp_sentry（外部守护进程）IPC 通信、无锁环形日志队列、以及极轻量级的 JSON 解析
// =========================================================================
static INIT_ONCE s_logCsOnce = INIT_ONCE_STATIC_INIT;
static std::atomic<long> s_hostLivenessThreads{0};

static std::atomic<int> s_minCsaLogLevel{0};

static int SeverityToCsaLevel(RaspDiagSeverity severity)
{
    switch (severity) {
        case RaspDiagSeverity::Debug:   return 7;
        case RaspDiagSeverity::Info:    return 6;
        case RaspDiagSeverity::Warning: return 4;
        case RaspDiagSeverity::Error:   return 3;
        default:                        return 6;
    }
}

static void LoadAmsiLogConfOnce()
{
    static std::atomic<bool> loaded{false};
    bool expected = false;
    if (!loaded.compare_exchange_strong(expected, true)) {
        return;
    }
    wchar_t dllDir[MAX_PATH] = {};
    HMODULE hMod = GetModuleHandleW(L"hss_amsi.dll");
    if (hMod && GetModuleFileNameW(hMod, dllDir, MAX_PATH)) {
        wchar_t* lastSlash = wcsrchr(dllDir, L'\\');
        if (lastSlash) {
            *(lastSlash + 1) = L'\0';
        }
        wcscat_s(dllDir, MAX_PATH, L"amsi_log.conf");
    } else {
        wcscpy_s(dllDir, MAX_PATH, L"amsi_log.conf");
    }
    HANDLE hFile = CreateFileW(dllDir, GENERIC_READ, FILE_SHARE_READ,
                               nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }
    char buf[32] = {};
    DWORD bytesRead = 0;
    if (ReadFile(hFile, buf, sizeof(buf) - 1, &bytesRead, nullptr) && bytesRead > 0) {
        buf[bytesRead] = '\0';
        int level = atoi(buf);
        if (level > 0) {
            s_minCsaLogLevel.store(level, std::memory_order_relaxed);
        }
    }
    CloseHandle(hFile);
}

namespace {

struct HostStateEnvelope {
    bool present = false;
    std::string state;
    std::string desiredRuntimeState;
    std::string stateVersion;
    std::string ruleVersion;
    std::string requiredDllHash;
    std::string rulesJson;
};

std::string NormalizeHashForCompare(std::string value)
{
    value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char ch) {
                    return std::isspace(ch) != 0;
                }),
                value.end());
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string HexBytes(const unsigned char* data, size_t len)
{
    static const char kHex[] = "0123456789abcdef";
    std::string out;
    out.resize(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out[i * 2] = kHex[(data[i] >> 4) & 0x0f];
        out[i * 2 + 1] = kHex[data[i] & 0x0f];
    }
    return out;
}

std::wstring CurrentModulePath()
{
    HMODULE module = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(&CurrentModulePath),
                            &module) || module == nullptr) {
        return std::wstring();
    }

    std::wstring path;
    path.resize(MAX_PATH);
    for (;;) {
        DWORD len = GetModuleFileNameW(module, &path[0], static_cast<DWORD>(path.size()));
        if (len == 0) {
            return std::wstring();
        }
        if (len < path.size() - 1) {
            path.resize(len);
            return path;
        }
        path.resize(path.size() * 2);
    }
}

std::string Sha256FileHex(const std::wstring& path)
{
    HANDLE file = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return std::string();
    }

    BCRYPT_ALG_HANDLE alg = nullptr;
    BCRYPT_HASH_HANDLE hash = nullptr;
    std::string result;
    DWORD hashLen = 0;
    DWORD cbData = 0;

    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) == 0 &&
        BCryptGetProperty(alg, BCRYPT_HASH_LENGTH,
                          reinterpret_cast<PUCHAR>(&hashLen),
                          sizeof(hashLen), &cbData, 0) == 0 &&
        hashLen > 0 &&
        BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0) == 0) {
        unsigned char buffer[64 * 1024];
        bool ok = true;
        for (;;) {
            DWORD readBytes = 0;
            if (!ReadFile(file, buffer, sizeof(buffer), &readBytes, nullptr)) {
                ok = false;
                break;
            }
            if (readBytes == 0) {
                break;
            }
            if (BCryptHashData(hash, buffer, readBytes, 0) != 0) {
                ok = false;
                break;
            }
        }
        if (ok) {
            std::vector<unsigned char> hashBytes(hashLen);
            if (BCryptFinishHash(hash, hashBytes.data(), hashLen, 0) == 0) {
                result = HexBytes(hashBytes.data(), hashBytes.size());
            }
        }
    }

    if (hash) {
        BCryptDestroyHash(hash);
    }
    if (alg) {
        BCryptCloseAlgorithmProvider(alg, 0);
    }
    CloseHandle(file);
    return result;
}

std::string CurrentModuleSha256Hex()
{
    static INIT_ONCE once = INIT_ONCE_STATIC_INIT;
    static std::string cachedHash;
    InitOnceExecuteOnce(&once,
                        [](PINIT_ONCE, PVOID, PVOID*) -> BOOL {
                            cachedHash = Sha256FileHex(CurrentModulePath());
                            return TRUE;
                        },
                        nullptr,
                        nullptr);
    return cachedHash;
}

bool TryParseHostStateEnvelope(const std::string& response, HostStateEnvelope& envelope)
{
    envelope = HostStateEnvelope{};
    RuleJsonParser::Parser parser(response.data(), response.size());
    if (!parser.consume('{')) {
        return false;
    }

    while (!parser.peek('}') && parser.ok()) {
        std::string key;
        if (!parser.read_string(key) || !parser.consume(':')) {
            return false;
        }

        if (key == "state") {
            if (!parser.read_string(envelope.state)) {
                parser.skip_value();
            }
        } else if (key == "desiredRuntimeState") {
            if (!parser.read_string(envelope.desiredRuntimeState)) {
                parser.skip_value();
            }
        } else if (key == "stateVersion") {
            if (!parser.read_string(envelope.stateVersion)) {
                parser.skip_value();
            }
        } else if (key == "ruleVersion") {
            if (!parser.read_string(envelope.ruleVersion)) {
                parser.skip_value();
            }
        } else if (key == "requiredDllHash") {
            if (!parser.read_string(envelope.requiredDllHash)) {
                parser.skip_value();
            }
        } else if (key == "rules") {
            parser.skip_ws();
            const char* begin = parser.p;
            parser.skip_value();
            const char* end = parser.p;
            if (end > begin) {
                envelope.rulesJson.assign(begin, static_cast<size_t>(end - begin));
            }
        } else {
            parser.skip_value();
        }

        parser.consume(',');
    }

    envelope.present = !envelope.state.empty();
    return envelope.present;
}

} // namespace

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

void RaspSentryBase::MarkWaitingResumeAfterHostLost(bool waiting)
{
    m_waitingResumeAfterHostLost.store(waiting, std::memory_order_release);
}

bool RaspSentryBase::IsHostAlive() const
{
    return m_hostAlive.load(std::memory_order_acquire);
}

bool RaspSentryBase::IsRuleSnapshotReady() const
{
    return m_ruleSnapshotReady.load(std::memory_order_acquire);
}

bool RaspSentryBase::IsWaitingResumeAfterHostLost() const
{
    return m_waitingResumeAfterHostLost.load(std::memory_order_acquire);
}

bool RaspSentryBase::ShouldBypassScanFast() const
{
    if (!m_running.load(std::memory_order_acquire))
        return true;
    if (m_upgradeInert.load(std::memory_order_acquire))
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
    // and HANDLE (m_logEvent) this INIT_ONCE is just a one-time initializer flag
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
// Log() public; thread-safe; writes to OutputDebugString AND ring buffer.
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
    LoadAmsiLogConfOnce();

    int minLevel = s_minCsaLogLevel.load(std::memory_order_relaxed);
    if (minLevel > 0 && SeverityToCsaLevel(severity) > minLevel) {
#ifdef _DEBUG
        char buf[1024];
        int n = vsnprintf(buf, sizeof(buf), fmt, ap);
        if (n >= (int)sizeof(buf)) {
            static const char kTrunc[] = "...<truncated>";
            memcpy(buf + sizeof(buf) - sizeof(kTrunc), kTrunc, sizeof(kTrunc));
        }
        int len = (int)strlen(buf);
        if (len > 0 && buf[len - 1] != '\n' && len < (int)sizeof(buf) - 1) {
            buf[len] = '\n';
            buf[len + 1] = '\0';
        }
        OutputDebugStringA(buf);
#endif
        return;
    }

    char buf[1024];
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);

    if (n >= (int)sizeof(buf))
    {
        static const char kTrunc[] = "...<truncated>";
        memcpy(buf + sizeof(buf) - sizeof(kTrunc), kTrunc, sizeof(kTrunc));
    }

#ifdef _DEBUG
    int len = (int)strlen(buf);
    if (len > 0 && buf[len - 1] != '\n' && len < (int)sizeof(buf) - 1)
    {
        buf[len]     = '\n';
        buf[len + 1] = '\0';
    }
    OutputDebugStringA(buf);
#endif

    // Cast away const - ring buffer mutation is logically non-observable to callers.
    const_cast<RaspSentryBase*>(this)->EnqueueLog(buf, severity);
}
/*
 * 功能：极低开销的无自旋锁日志记
 * 流程：Log 写入环形数组（如果满了就覆盖最老的> 触发 m_logEvent -> 后台线程 LogForwardThreadProc 醒来 ->
 * 拼装JSON -> 通过命名管道 \\.\pipe\amsi_detect_events 发出
 * Mark: 日志限制长度(防止恶意日志填满缓冲
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

// 调用方必须已经持m_logCs
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
// Base64 decoder 可以添加一个输入、输出长度限制（防止dos攻击
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
// ConnectSentry 在启动时，连接命名管道，发GET_ALL_RULES，阻塞读取并拉取完整的安全策JSON
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
    metadataOut = RuleBundleMetadata{};

    if (!WaitNamedPipeW(L"\\\\.\\pipe\\amsi_detect_rules", 100))
    {
        LogWithSeverity(RaspDiagSeverity::Warning, "ConnectSentry: pipe not available");
        return false;
    }

    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\amsi_detect_rules",
                               GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE)
    {
        LogWithSeverity(RaspDiagSeverity::Error, "ConnectSentry: CreateFileW failed GLE=%lu", GetLastError());
        return false;
    }

    DWORD mode = PIPE_READMODE_MESSAGE;
    if (!SetNamedPipeHandleState(hPipe, &mode, nullptr, nullptr))
    {
        LogWithSeverity(RaspDiagSeverity::Error, "ConnectSentry: SetNamedPipeHandleState failed GLE=%lu", GetLastError());
        CloseHandle(hPipe);
        return false;
    }

    const char req[] = "GET_ALL_RULES\n";
    DWORD written = 0;
    if (!WriteFile(hPipe, req, (DWORD)strlen(req), &written, nullptr) || written == 0)
    {
        LogWithSeverity(RaspDiagSeverity::Error, "ConnectSentry: WriteFile failed GLE=%lu", GetLastError());
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
        LogWithSeverity(RaspDiagSeverity::Error, "ConnectSentry: ReadFile failed GLE=%lu bytes=%lu", readErr, bytesRead);
        return false;
    }
    response.resize(bytesRead);

    RuleBundleMetadata envelopeMetadata;
    HostStateEnvelope envelope;
    if (TryParseHostStateEnvelope(response, envelope)) {
        const std::string runtimeState = envelope.desiredRuntimeState.empty()
                                         ? envelope.state
                                         : envelope.desiredRuntimeState;
        if (runtimeState == "unloading" || envelope.state == "unload") {
            m_upgradeInert.store(true, std::memory_order_release);
            MarkHostAlive(true);
            MarkDetectionPausedByHostState(true);
            MarkRuleSnapshotReady(false);
            MarkWaitingResumeAfterHostLost(true);
            LogWithSeverity(RaspDiagSeverity::Warning,
                            "ConnectSentry: host requested DLL unloading stateVersion=%s - entering upgrade inert mode",
                            envelope.stateVersion.c_str());
            OnUnloadSignal();
            return false;
        }
        if (!envelope.requiredDllHash.empty()) {
            const std::string requiredDllHash = NormalizeHashForCompare(envelope.requiredDllHash);
            const std::string currentDllHash = CurrentModuleSha256Hex();
            if (currentDllHash.empty() || currentDllHash != requiredDllHash) {
                m_upgradeInert.store(true, std::memory_order_release);
                MarkHostAlive(true);
                MarkDetectionPausedByHostState(true);
                MarkRuleSnapshotReady(false);
                MarkWaitingResumeAfterHostLost(true);
                LogWithSeverity(RaspDiagSeverity::Warning,
                                "ConnectSentry: requiredDllHash mismatch required=%s current=%s - entering upgrade inert mode",
                                requiredDllHash.c_str(),
                                currentDllHash.empty() ? "unknown" : currentDllHash.c_str());
                OnUnloadSignal();
                return false;
            }
        }
        if (m_upgradeInert.load(std::memory_order_acquire)) {
            LogWithSeverity(RaspDiagSeverity::Warning, "ConnectSentry: ignoring host state=%s because upgrade inert is already set",
                runtimeState.c_str());
            return false;
        }
        if (runtimeState != "running") {
            LogWithSeverity(RaspDiagSeverity::Warning,
                            "ConnectSentry: unsupported host desiredRuntimeState=%s state=%s",
                            runtimeState.c_str(), envelope.state.c_str());
            return false;
        }
        if (envelope.rulesJson.empty()) {
            LogWithSeverity(RaspDiagSeverity::Warning, "ConnectSentry: host state envelope missing rules");
            return false;
        }
        response = envelope.rulesJson;
        envelopeMetadata.version = envelope.ruleVersion;
    }

    jsonOut = response;

    // Pre-extract the lib source so callers (SentryRetryThreadProc, Initialize)
    // can pass it directly to ParseAndSwap. ParseAndSwap re-parses the JSON to
    // build its typed snapshot. If a state envelope supplied ruleVersion, keep it
    // as metadata when the inner rules JSON does not carry a version field.
    libSourceOut.clear();
    std::vector<std::unique_ptr<RaspRuleBase>> dummy;
    RuleBundleMetadata parsedMetadata;
    ParseRulesJson(response, libSourceOut, dummy, &parsedMetadata);
    metadataOut = parsedMetadata;
    if (metadataOut.version.empty()) {
        metadataOut.version = envelopeMetadata.version;
    }
    if (metadataOut.hash.empty()) {
        metadataOut.hash = envelopeMetadata.hash;
    }
    return true;
}

/*
 * 递归解析检查项数组
 * */
// =========================================================================
// ParseRulesJson base-field parser
// =========================================================================

void RaspSentryBase::ParseRuleExtension(const std::string& /*key*/,
                                        void*              parserPtr,
                                        RaspRuleBase&      /*rule*/)
{
    // Default: skip unrecognised value so the parser advances past it.
    static_cast<Parser*>(parserPtr)->skip_value();
}

/*
 * 轻量级流JSON 解析器、避免引入巨大的第三JSON
 * */
bool RaspSentryBase::ParseRulesJson(
    const std::string&                          json,
    std::string&                                libSourceOut,
    std::vector<std::unique_ptr<RaspRuleBase>>& rulesOut,
    RuleBundleMetadata*                         metadataOut,
    std::vector<std::string>*                   trustProcessOut,
    RaspGlobalMode*                             globalModeOut,
    bool*                                       hasGlobalModeOut,
    uint32_t*                                   maxScanContentBytesOut,
    uint32_t*                                   auditMaxEventsPerScanOut,
    bool*                                       stopAfterFirstBlockOut,
    uint32_t*                                   totalScanTimeoutMsOut,
    ScanRateLimitConfig*                        scanRateLimitOut,
    bool*                                       hasScanRateLimitOut)
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
    if (globalModeOut)
        *globalModeOut = result.globalMode;
    if (hasGlobalModeOut)
        *hasGlobalModeOut = result.hasGlobalMode;
    if (maxScanContentBytesOut)
        *maxScanContentBytesOut = result.maxScanContentBytes;
    if (auditMaxEventsPerScanOut)
        *auditMaxEventsPerScanOut = result.auditMaxEventsPerScan;
    if (stopAfterFirstBlockOut)
        *stopAfterFirstBlockOut = result.stopAfterFirstBlock;
    if (totalScanTimeoutMsOut)
        *totalScanTimeoutMsOut = result.totalScanTimeoutMs;
    if (scanRateLimitOut)
        *scanRateLimitOut = result.scanRateLimit;
    if (hasScanRateLimitOut)
        *hasScanRateLimitOut = result.hasScanRateLimit;
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

static std::string LocalCompactTimestamp()
{
    SYSTEMTIME st;
    GetLocalTime(&st);
    char buf[32];
    snprintf(buf, sizeof(buf), "%04d%02d%02d %02d:%02d:%02d",
             st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
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
    input.timestamp = LocalCompactTimestamp();
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

    LegacyDiagJsonBuildInput diagInput;
    FillDiagnosticLogContext(diagInput);

    char parentPidBuf[32];
    snprintf(parentPidBuf, sizeof(parentPidBuf), "%lu", static_cast<unsigned long>(diagInput.parentPid));

    char json[3072];
    _snprintf_s(json, sizeof(json), _TRUNCATE,
                "{\"msgType\":\"RULE_LOAD_RESULT\","
                "\"module\":\"amsi_detect\","
                "\"dllInstanceId\":\"%s\","
                "\"pid\":%s,"
                "\"processName\":\"%s\","
                "\"processPath\":\"%s\","
                "\"parentPid\":%s,"
                "\"parentProcessName\":\"%s\","
                "\"parentProcessPath\":\"%s\","
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
                ControlStatusJsonEscape(diagInput.processName).c_str(),
                ControlStatusJsonEscape(diagInput.processPath).c_str(),
                parentPidBuf,
                ControlStatusJsonEscape(diagInput.parentProcessName).c_str(),
                ControlStatusJsonEscape(diagInput.parentProcessPath).c_str(),
                ControlStatusJsonEscape(LocalCompactTimestamp()).c_str(),
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
        LogWithSeverity(RaspDiagSeverity::Warning, "SendRuleLoadResult: control status pipe unavailable GLE=%lu", GetLastError());
        return;
    }

    DWORD written = 0;
    const DWORD expected = static_cast<DWORD>(strlen(json));
    if (!WriteFile(hPipe, json, expected, &written, nullptr) || written != expected)
    {
        LogWithSeverity(RaspDiagSeverity::Warning, "SendRuleLoadResult: WriteFile failed GLE=%lu written=%lu expected=%lu", GetLastError(), written, expected);
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

std::string RaspSentryBase::ComputeEffectiveSnapshotHash(const std::string& rulesJson)
{
    uint64_t hash = 1469598103934665603ull;
    for (unsigned char ch : rulesJson) {
        hash ^= static_cast<uint64_t>(ch);
        hash *= 1099511628211ull;
    }

    char buf[17] = {};
    std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(hash));
    return std::string(buf);
}

void RaspSentryBase::SetActiveEffectiveSnapshotHash(const std::string& hash)
{
    std::lock_guard<std::mutex> lock(m_ruleMetadataMutex);
    m_activeEffectiveSnapshotHash = hash;
}

std::string RaspSentryBase::ActiveEffectiveSnapshotHash() const
{
    std::lock_guard<std::mutex> lock(m_ruleMetadataMutex);
    return m_activeEffectiveSnapshotHash;
}

/**
 * 新增日志添加进程信息
 * @param input
 */
void RaspSentryBase::FillDiagnosticLogContext(LegacyDiagJsonBuildInput& input) const
{
    DWORD pid = GetCurrentProcessId();
    input.pid = static_cast<uint32_t>(pid);
    char pidText[16] = {};
    std::snprintf(pidText, sizeof(pidText), "%lu", static_cast<unsigned long>(pid));
    input.dllInstanceId = std::string("amsi_detect_") + pidText;
}

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
            input.timestamp = LocalCompactTimestamp();
            input.module = self->ModuleName();
            input.message = entryText;
            input.severity = entrySeverity;
            self->FillDiagnosticLogContext(input);  // 填充信息

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
                self->Log("Host rule pipe visible again, waiting active rule poll/reload before detection resumes");
            }

            self->SleepHostLivenessInterruptible(self->m_probeIntervalMs);
            continue;
        }

        if (consecutiveFailures == 0) {
            firstFailureTick = now;
            if (!graceLogged) {
                self->LogWithSeverity(RaspDiagSeverity::Debug,
                                      "Host liveness probe failed, entering grace period");
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
                                      "Host liveness lost, pause AMSI detection until host reload/resume");
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
// SentryRetryThreadProc - actively polls Host state/rules through amsi_detect_rules.
// Reload broadcasts are only acceleration hints; this thread is the fallback that
// lets already-loaded DLLs recover or update when they miss a broadcast.
// =========================================================================

DWORD WINAPI RaspSentryBase::SentryRetryThreadProc(LPVOID param)
{
    auto* self = static_cast<RaspSentryBase*>(param);
    self->LogWithSeverity(RaspDiagSeverity::Debug,"RulePollThread: started - retry=%lums interval=%lums", self->m_rulePollRetryIntervalMs, self->m_rulePollIntervalMs);

    while (self->m_running.load(std::memory_order_acquire))
    {
        const bool ready = self->IsRuleSnapshotReady();
        const bool alive = self->IsHostAlive();
        const DWORD sleepMs = (ready && alive) ? self->m_rulePollIntervalMs : self->m_rulePollRetryIntervalMs;
        DWORD elapsed = 0;
        while (self->m_running.load(std::memory_order_acquire) && elapsed < sleepMs) {
            if ((ready && alive) && (!self->IsRuleSnapshotReady() || !self->IsHostAlive())) {
                break;
            }
            const DWORD slice = (sleepMs - elapsed) > 100 ? 100 : (sleepMs - elapsed);
            Sleep(slice);
            elapsed += slice;
        }

        if (!self->m_running.load(std::memory_order_acquire)) {
            break;
        }

        std::string json;
        std::string lib;
        RuleBundleMetadata requestedMetadata;
        if (!self->ConnectSentry(json, lib, requestedMetadata)) {
            if (!self->IsRuleSnapshotReady()) {
                self->Log("RulePollThread: host/rules unavailable - detection remains bypassed");
            }
            continue;
        }

        const RuleBundleMetadata activeMetadata = self->ActiveRuleMetadataForStatus();
        const std::string requestedEffectiveHash = self->ComputeEffectiveSnapshotHash(json);
        const std::string activeEffectiveHash = self->ActiveEffectiveSnapshotHash();
        const bool snapshotReady = self->IsRuleSnapshotReady();
        const bool versionChanged = !requestedMetadata.version.empty() &&
                                    requestedMetadata.version != activeMetadata.version;
        const bool hashChanged = !requestedMetadata.hash.empty() &&
                                 requestedMetadata.hash != activeMetadata.hash;
        const bool effectiveHashMissing = snapshotReady && activeEffectiveHash.empty();
        const bool effectiveHashChanged = !requestedEffectiveHash.empty() &&
                                          requestedEffectiveHash != activeEffectiveHash;
        const bool needLoad = !snapshotReady ||
                              self->IsWaitingResumeAfterHostLost() ||
                              versionChanged ||
                              hashChanged ||
                              effectiveHashMissing ||
                              effectiveHashChanged;

        self->MarkHostAlive(true);
        if (!needLoad) {
            if (self->m_hostDetectionPaused.load(std::memory_order_acquire)) {
                self->MarkDetectionPausedByHostState(false);
                self->MarkWaitingResumeAfterHostLost(false);
                self->Log("RulePollThread: host running with current rules - detection resumed");
            }
            continue;
        }

        if (self->ParseAndSwap(json, lib)) {
            self->SetActiveRuleMetadataForStatus(requestedMetadata);
            self->SetActiveEffectiveSnapshotHash(requestedEffectiveHash);
            self->MarkRuleSnapshotReady(true);
            self->MarkDetectionPausedByHostState(false);
            self->MarkWaitingResumeAfterHostLost(false);
            self->Log("RulePollThread: rules loaded version=%s hash=%s - detection resumed", requestedMetadata.version.c_str(), requestedMetadata.hash.c_str());
            self->SendRuleLoadResult(true, 0, "", requestedMetadata);
            continue;
        }

        self->MarkRuleSnapshotReady(false);
        self->MarkDetectionPausedByHostState(true);
        self->MarkWaitingResumeAfterHostLost(true);
        self->LogWithSeverity(RaspDiagSeverity::Warning,
                              "RulePollThread: rule load failed - detection remains bypassed");
        self->SendRuleLoadResult(false, 3, "active rule poll load failed", requestedMetadata);
    }

    self->Log("RulePollThread: exiting");
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
    m_waitingResumeAfterHostLost.store(false, std::memory_order_release);
    m_upgradeInert.store(false, std::memory_order_release);
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
    //  the existing pattern see their OnBeginInit hooks.)

    LogWithSeverity(RaspDiagSeverity::Debug,"Initialize: starting - all config via sentry IPC");

    std::string json, lib;
    RuleBundleMetadata requestedMetadata;
    bool connected = ConnectSentry(json, lib, requestedMetadata);
    const std::string requestedEffectiveHash = connected ? ComputeEffectiveSnapshotHash(json) : std::string();
    bool loaded = connected && ParseAndSwap(json, lib);

    if (loaded)
    {
        SetActiveRuleMetadataForStatus(requestedMetadata);
        SetActiveEffectiveSnapshotHash(requestedEffectiveHash);
        MarkHostAlive(true);
        MarkRuleSnapshotReady(true);
        MarkDetectionPausedByHostState(false);
        MarkWaitingResumeAfterHostLost(false);
        LogWithSeverity(RaspDiagSeverity::Debug, "Initialize: rules loaded from sentry");
        SendRuleLoadResult(true, 0, "", requestedMetadata);
    }
    else
    {
        MarkHostAlive(false);
        MarkRuleSnapshotReady(false);
        MarkDetectionPausedByHostState(true);
        MarkWaitingResumeAfterHostLost(true);
        SendRuleLoadResult(false,
                           connected ? 3 : 1,
                           connected ? "initial rule load failed" : "rules pipe unavailable",
                           requestedMetadata);
        Log("Initialize: sentry unavailable - pass-through; active rule polling will retry");
    }

    m_retryThread = CreateThread(nullptr, 0, SentryRetryThreadProc, this, 0, nullptr);
    if (m_retryThread == INVALID_HANDLE_VALUE || m_retryThread == nullptr) {
        LogWithSeverity(RaspDiagSeverity::Warning,
                        "Initialize: failed to start active rule poll thread GLE=%lu", GetLastError());
        m_retryThread = INVALID_HANDLE_VALUE;
    }
    m_hostLivenessThread = CreateThread(nullptr, 0, HostLivenessThreadProc, this, 0, nullptr);
    if (m_hostLivenessThread == INVALID_HANDLE_VALUE || m_hostLivenessThread == nullptr) {
        MarkHostAlive(false);
        MarkRuleSnapshotReady(false);
        MarkDetectionPausedByHostState(true);
        MarkWaitingResumeAfterHostLost(true);
        LogWithSeverity(RaspDiagSeverity::Warning,
                        "Initialize: failed to start host liveness watcher GLE=%lu - detection paused", GetLastError());
        m_hostLivenessThread = INVALID_HANDLE_VALUE;
    }
    m_logThread    = CreateThread(nullptr, 0, LogForwardThreadProc,  this, 0, nullptr);

    LogWithSeverity(RaspDiagSeverity::Debug,"Initialize: RulePollThread + HostLivenessThread + LogForwardThread started");
}

void RaspSentryBase::Shutdown()
{
    m_running.store(false, std::memory_order_release);
    m_hostLivenessStop.store(true, std::memory_order_release);
    m_hostDetectionPaused.store(true, std::memory_order_release);
    m_ruleSnapshotReady.store(false, std::memory_order_release);
    m_waitingResumeAfterHostLost.store(true, std::memory_order_release);
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
    // 3. Drain log thread last (final flush after other background threads stop)
    m_logThreadAlive = false;
    if (m_logEvent) SetEvent(m_logEvent);
    if (m_logThread != INVALID_HANDLE_VALUE)
    {
        WaitForSingleObject(m_logThread, 3000);
        CloseHandle(m_logThread);
        m_logThread = INVALID_HANDLE_VALUE;
    }
}