// =========================================================================
// rasp_sentry_base.cpp 鈥?Shared RASP infrastructure (log, IPC, threads).
//
// Extracted verbatim from iis7_rule_engine.cpp and amsi_rule_engine.cpp.
// Contains all code that was duplicated between the two modules:
//   - Ring-buffer diagnostic log + INIT_ONCE init + Log()
//   - Base64Decode
//   - ConnectSentry() IPC handshake (GET_ALL_RULES)
//   - ParseRulesJson()  (base-field recursive-descent parser)
//   - SendDetectionEvent() (replaces amsi_event_sender::SendAmsiEvent)
//   - LogForwardThreadProc  (ring-buffer drain 鈫?rasp_sentry_events)
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
#include <sstream>

#include "../include/rasp_sentry_base.h"

// =========================================================================
// 澶勭悊鎵€鏈変笌 rasp_sentry锛堝閮ㄥ畧鎶よ繘绋嬶級鐨?IPC 閫氫俊銆佹棤閿佺幆褰㈡棩蹇楅槦鍒椼€佷互鍙婃瀬杞婚噺绾х殑 JSON 瑙ｆ瀽
// =========================================================================
static INIT_ONCE s_logCsOnce = INIT_ONCE_STATIC_INIT;

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

static BOOL WINAPI LogCsInit(INIT_ONCE*, PVOID, PVOID*)
{
    // NOTE: Each RaspSentryBase instance owns its own CRITICAL_SECTION (m_logCs)
    // and HANDLE (m_logEvent) 鈥?this INIT_ONCE is just a one-time initializer flag
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
// Log() 鈥?public; thread-safe; writes to OutputDebugString AND ring buffer.
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

    // Cast away const 鈥?ring buffer mutation is logically non-observable to callers.
    const_cast<RaspSentryBase*>(this)->EnqueueLog(buf);
}
/*
 * 鍔熻兘锛氭瀬浣庡紑閿€鐨勬棤閿?鑷棆閿佹棩蹇楄褰? * 娴佺▼锛歀og 鍐欏叆鐜舰鏁扮粍锛堝鏋滄弧浜嗗氨瑕嗙洊鏈€鑰佺殑锛?> 瑙﹀彂 m_logEvent -> 鍚庡彴绾跨▼ LogForwardThreadProc 閱掓潵 ->
 * 鎷艰涓?JSON -> 閫氳繃鍛藉悕绠￠亾 \\.\pipe\rasp_sentry_events 鍙戝嚭
 * Mark: 鏃ュ織闄愬埗闀垮害(闃叉鎭舵剰鏃ュ織濉弧缂撳啿鍖?
 * */
void RaspSentryBase::EnqueueLog(const char* text)
{
    EnsureLogCsInit();
    EnterCriticalSection(&m_logCs);
    {
        if (m_logCount >= kLogQueueCap)
            m_logTail = (m_logTail + 1) % kLogQueueCap;   // evict oldest
        else
            InterlockedIncrement(&m_logCount);

        int slot = (int)(m_logHead % kLogQueueCap);
        strncpy_s(m_logQueue[slot].text, sizeof(m_logQueue[slot].text), text, _TRUNCATE);
        m_logHead = (m_logHead + 1) % kLogQueueCap;
    }
    LeaveCriticalSection(&m_logCs);

    if (m_logEvent) SetEvent(m_logEvent);
}

// =========================================================================
// Base64 decoder 鈥?鍙互娣诲姞涓€涓緭鍏ャ€佽緭鍑洪暱搴﹂檺鍒讹紙闃叉dos鏀诲嚮锛?// =========================================================================
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
// ConnectSentry 鈥?鍦ㄥ惎鍔ㄦ椂锛岃繛鎺ュ懡鍚嶇閬擄紝鍙戦€?GET_ALL_RULES锛岄樆濉炶鍙栧苟鎷夊彇瀹屾暣鐨勫畨鍏ㄧ瓥鐣?JSON
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

    Log("[%s] ConnectSentry: received %lu bytes - parsing", ModuleName(), bytesRead);

    jsonOut = response;

    // Pre-extract the lib source so callers (SentryRetryThreadProc, Initialize)
    // can pass it directly to ParseAndSwap. ParseAndSwap re-parses the JSON to
    // build its typed snapshot 鈥?the double parse is acceptable at init/reload time.
    libSourceOut.clear();
    std::vector<std::unique_ptr<RaspRuleBase>> dummy;
    ParseRulesJson(response, libSourceOut, dummy);

    Log("[%s] ConnectSentry: %zu rule(s) found, lib=%zu bytes",
        ModuleName(), dummy.size(), libSourceOut.size());
    return true;
}

// =========================================================================
// Parser method implementations
// =========================================================================

bool RaspSentryBase::Parser::read_string(std::string& out)
{
    if (!consume('"')) return false;
    out.clear();
    while (p < end && *p != '"')
    {
        if (*p == '\\') { ++p; if (p < end) { out += *p; ++p; } }
        else            { out += *p++; }
    }
    return consume('"');
}

bool RaspSentryBase::Parser::read_bool(bool& out)
{
    skip_ws();
    if (p + 4 <= end && strncmp(p, "true",  4) == 0) { out = true;  p += 4; return true; }
    if (p + 5 <= end && strncmp(p, "false", 5) == 0) { out = false; p += 5; return true; }
    return false;
}

bool RaspSentryBase::Parser::read_int(int& out)
{
    skip_ws();
    if (!ok()) return false;
    bool neg = false;
    if (*p == '-') { neg = true; ++p; }
    if (!ok() || !isdigit((unsigned char)*p)) return false;
    out = 0;
    while (ok() && isdigit((unsigned char)*p))
        out = out * 10 + (*p++ - '0');
    if (neg) out = -out;
    return true;
}

bool RaspSentryBase::Parser::read_string_array(std::vector<std::string>& out)
{
    if (!consume('[')) return false;
    out.clear();
    while (!peek(']'))
    {
        std::string s;
        if (!read_string(s)) { skip_value(); break; }
        out.push_back(s);
        consume(',');
    }
    return consume(']');
}
/*
 * 閫掑綊瑙ｆ瀽妫€鏌ラ」鏁扮粍
 * */
bool RaspSentryBase::Parser::read_regex_check_array(std::vector<RegexCheck>& out)
{
    if (!consume('[')) return false;
    out.clear();
    while (!peek(']') && ok())
    {
        if (!consume('{')) { skip_value(); consume(','); continue; }
        RegexCheck chk;
        while (!peek('}') && ok())
        {
            std::string key;
            if (!read_string(key) || !consume(':')) break;
            if      (key == "id")       read_string(chk.id);
            else if (key == "field")    read_string(chk.field);
            else if (key == "patterns") read_string_array(chk.patterns);
            else                        skip_value();
            consume(',');
        }
        consume('}');
        if (!chk.id.empty() && !chk.patterns.empty())
            out.push_back(std::move(chk));
        consume(',');
    }
    return consume(']');
}

void RaspSentryBase::Parser::skip_value()
{
    skip_ws();
    if (!ok()) return;
    if (*p == '"') { std::string d; read_string(d); return; }
    if (*p == '{') { skip_object(); return; }
    if (*p == '[') { skip_array();  return; }
    while (ok() && *p != ',' && *p != '}' && *p != ']' &&
           *p != ' '  && *p != '\t' && *p != '\r' && *p != '\n')
        ++p;
}

void RaspSentryBase::Parser::skip_array()
{
    consume('[');
    while (!peek(']') && ok()) { skip_value(); consume(','); }
    consume(']');
}

void RaspSentryBase::Parser::skip_object()
{
    consume('{');
    while (!peek('}') && ok())
    {
        std::string key; read_string(key); consume(':'); skip_value(); consume(',');
    }
    consume('}');
}

// =========================================================================
// ParseRulesJson 鈥?base-field parser
// =========================================================================

void RaspSentryBase::ParseRuleExtension(const std::string& /*key*/,
                                        void*              parserPtr,
                                        RaspRuleBase&      /*rule*/)
{
    // Default: skip unrecognised value so the parser advances past it.
    static_cast<Parser*>(parserPtr)->skip_value();
}

/*
 * 杞婚噺绾ф祦寮?JSON 瑙ｆ瀽鍣ㄣ€侀伩鍏嶅紩鍏ュ法澶х殑绗笁鏂?JSON 搴? * */
bool RaspSentryBase::ParseRulesJson(
    const std::string&                          json,
    std::string&                                libSourceOut,
    std::vector<std::unique_ptr<RaspRuleBase>>& rulesOut)
{
    if (json.empty()) return false;

    libSourceOut.clear();
    rulesOut.clear();

    Parser p(json.c_str(), json.size());
    if (!p.consume('{')) return false;

    while (!p.peek('}') && p.ok())
    {
        std::string key;
        if (!p.read_string(key) || !p.consume(':')) break;

        if (key == "globalLibrariesBase64" || key == "globalLibraries")
        {
            // Array of base64 strings: ["<b64>", "<b64>", ...]
            // Also accept bare single string for backward compat.
            p.skip_ws();
            if (p.peek('['))
            {
                std::vector<std::string> items;
                p.read_string_array(items);
                for (const auto& b64 : items)
                {
                    std::string decoded;
                    if (Base64Decode(b64, decoded))
                        libSourceOut += decoded + "\n";
                }
            }
            else
            {
                // Bare string (legacy / AMSI single-library format)
                std::string b64;
                p.read_string(b64);
                std::string decoded;
                if (!b64.empty() && Base64Decode(b64, decoded))
                    libSourceOut = decoded;
            }
        }
        else if (key == "rules")
        {
            if (!p.consume('[')) { p.skip_value(); p.consume(','); continue; }

            while (!p.peek(']') && p.ok())
            {
                if (!p.peek('{')) { p.skip_value(); p.consume(','); continue; }

                // Allocate the concrete rule type via the virtual factory.
                auto rulePtr = std::unique_ptr<RaspRuleBase>(AllocRule());
                RaspRuleBase& rule = *rulePtr;

                if (!p.consume('{')) { p.consume(','); continue; }

                while (!p.peek('}') && p.ok())
                {
                    std::string rkey;
                    if (!p.read_string(rkey) || !p.consume(':')) break;

                    // 鈹€鈹€ Base fields 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
                    if      (rkey == "id")               p.read_string(rule.id);
                    else if (rkey == "sensor")            p.read_string(rule.sensor);
                    else if (rkey == "enabled")           p.read_bool(rule.enabled);
                    else if (rkey == "description")       p.read_string(rule.description);
                    else if (rkey == "severity")          p.read_string(rule.severity);
                    else if (rkey == "scriptBodyBase64")  p.read_string(rule.scriptBodyBase64);
                    else if (rkey == "scriptEval")        p.read_string(rule.scriptEval);
                    else if (rkey == "confidence")        p.read_int(rule.confidence);
                    else if (rkey == "mode")
                    {
                        std::string m;
                        p.read_string(m);
                        if      (m == "block") rule.mode = RaspRuleMode::Block;
                        else if (m == "off")   rule.mode = RaspRuleMode::Off;
                        else                   rule.mode = RaspRuleMode::Audit;
                    }
                    else if (rkey == "scriptTimeoutMs")
                    {
                        int ms = 0; p.read_int(ms);
                        rule.scriptTimeoutInstructions = ms * 50000;
                        if (rule.scriptTimeoutInstructions <= 0)
                            rule.scriptTimeoutInstructions = 500000;
                    }
                    // 鈹€鈹€ Module-specific fields 鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€鈹€
                    else
                    {
                        // Derived classes override ParseRuleExtension to handle
                        // their sensor-specific keys. Default: skip the value.
                        ParseRuleExtension(rkey, &p, rule);
                    }

                    p.consume(',');
                }
                p.consume('}'); // close rule object

                if (!rule.id.empty())
                    rulesOut.push_back(std::move(rulePtr));

                p.consume(',');
            }
            p.consume(']');
        }
        else
        {
            p.skip_value();
        }

        p.consume(',');
    }

    return !rulesOut.empty();
}

// =========================================================================
// SendDetectionEvent 鈥?fire-and-forget JSONL to rasp_sentry_events
// Replaces amsi_event_sender::SendAmsiEvent(). Non-blocking 鈥?drops silently
// if sentry not running (0 ms WaitNamedPipe timeout, CreateFile returns ASAP).
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

static std::string SentryJsonEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (unsigned char c : s)
    {
        switch (c)
        {
        case '"':  out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\n': out += "\\n";  break;
        case '\r': out += "\\r";  break;
        case '\t': out += "\\t";  break;
        default:
            if (c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); out += b; }
            else           out += (char)c;
        }
    }
    return out;
}

} // anonymous namespace
/*
 * 闅愭偅锛氬彂閫佸憡璀︽椂锛屼娇鐢ㄤ簡 CreateFileW 鎵撳紑鍛藉悕绠￠亾涓?WaitNamedPipe 閮芥病鏈夌敤銆? * 濡傛灉鍚庣 rasp_sentry 姝ｅ湪澶勭悊楂樺苟鍙戯紝鎴栬€呯閬撶紦鍐插尯婊′簡锛孋reateFileW 鎴?WriteFile 浼氱珛鍒诲け璐ワ紝鍦ㄤ骇鍝佷腑鏃犳硶鎺ュ彈
 * 淇寤鸿锛氬簲褰撲负鍛婅浜嬩欢寮曞叆涓€涓被浼?EnqueueLog 鐨勫唴瀛樼幆褰㈢紦鍐查槦鍒?(Event Queue)锛岀敱涓撻棬鐨勫悗鍙扮嚎绋嬭礋璐ｄ繚璇佹姇閫掔殑鍙潬鎬э紙閲嶈瘯鏈哄埗锛? * */
void RaspSentryBase::SendDetectionEvent(const RaspEvalResult& result) const
{
    std::string id  = SentryGenerateEventId();
    std::string ts  = SentryUtcTimestamp();
    std::string sev = result.severity.empty() ? "High" : result.severity;
    std::string act = result.block ? "block" : "audit";
    std::string  confidence = result.confidence ? std::to_string(result.confidence): "70";

    std::ostringstream json;
    json << "{"
         << "\"id\":\""      << SentryJsonEscape(id)              << "\","
         << "\"ts\":\""      << SentryJsonEscape(ts)              << "\","
         << "\"sev\":\""     << SentryJsonEscape(sev)             << "\","
         << "\"act\":\""     << act                               << "\","
         << "\"cat\":\"Detection\","
         << "\"mod\":\""     << SentryJsonEscape(ModuleName())    << "\","
         << "\"sensor\":\""  << SentryJsonEscape(result.sensor)   << "\","
         << "\"rule\":\""    << SentryJsonEscape(result.ruleId)   << "\","
         << "\"desc\":\""    << SentryJsonEscape(result.desc)     << "\","
         << "\"appName\":\""  << SentryJsonEscape(result.appName)   << "\","
         << "\"contentName\":\""     << SentryJsonEscape(result.contentName)      << "\","
         << "\"confidence\":\""  << SentryJsonEscape(confidence)      << "\","
         << "\"ip\":\""      << SentryJsonEscape(result.ip)       << "\","
         << "\"ua\":\""      << SentryJsonEscape(result.ua)       << "\","
         << "\"pattern\":\""  << SentryJsonEscape(result.payload) << "\""
         << "}";

    std::string line = json.str();

    HANDLE hPipe = CreateFileW(L"\\\\.\\pipe\\rasp_sentry_events",
                               GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hPipe == INVALID_HANDLE_VALUE)
        return; // sentry not running 鈥?silently drop

    DWORD written = 0;
    WriteFile(hPipe, line.c_str(), (DWORD)line.size(), &written, nullptr);
    CloseHandle(hPipe);
}

// =========================================================================
// LogForwardThreadProc 鈥?drains ring buffer to rasp_sentry_events as diag events
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
            bool hasItem = (self->m_logCount > 0);
            if (hasItem)
            {
                int slot = (int)(self->m_logTail % kLogQueueCap);
                strncpy_s(entryText, sizeof(entryText),
                          self->m_logQueue[slot].text, _TRUNCATE);
                self->m_logTail = (self->m_logTail + 1) % kLogQueueCap;
                InterlockedDecrement(&self->m_logCount);
            }
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
// ConfigPipeThreadProc 鈥?server on \\.\pipe\rasp_sentry_config
// Dark period of 600ms after handling prevents BroadcastReload reconnect loop.
// (See AMSI ConfigPipeThread comments for full explanation.)
// =========================================================================

DWORD WINAPI RaspSentryBase::ConfigPipeThreadProc(LPVOID param)
{
    auto* self = static_cast<RaspSentryBase*>(param);

    self->Log("[%s] ConfigPipeThread: started", self->ModuleName());

    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, FALSE };
    PSECURITY_DESCRIPTOR configSd = nullptr;
    std::wstring configPipeSddl;
    if (!BuildCurrentUserConfigPipeSecurityAttributes(sa, configSd, configPipeSddl)) {
        self->Log("[%s] ConfigPipeThread: Fatal - failed to build secure SD GLE=%lu",
                  self->ModuleName(), GetLastError());
        return 0;
    }
    self->Log("[%s] ConfigPipeThread: using SDDL %ls",
              self->ModuleName(), configPipeSddl.c_str());

    auto CreateConfigPipe = [&sa]() -> HANDLE {
        return CreateNamedPipeW(
            L"\\\\.\\pipe\\rasp_sentry_config",
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            0, 1, 0, &sa);
    };

    while (self->m_running.load()) {
        HANDLE hPipe = CreateConfigPipe();
        if (hPipe == INVALID_HANDLE_VALUE) {
            self->Log("[%s] ConfigPipeThread: CreateNamedPipeW failed GLE=%lu - retrying in 1s",
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
        }
    }

    LocalFree(configSd);
    self->Log("[%s] ConfigPipeThread: exiting", self->ModuleName());
    return 0;
}

// =========================================================================
// SentryRetryThreadProc 鈥?polls ConnectSentry+ParseAndSwap every 5 s.
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
        if (self->ConnectSentry(json, lib) && self->ParseAndSwap(json, lib)) {
            self->Log("[%s] SentryRetryThread: rules loaded - exiting", self->ModuleName());
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
    //  the existing pattern 鈥?see their OnBeginInit hooks.)

    Log("[%s] Initialize: starting - all config via rasp_sentry IPC", ModuleName());

    std::string json, lib;
    bool loaded = ConnectSentry(json, lib) && ParseAndSwap(json, lib);

    if (loaded)
    {
        Log("[%s] Initialize: rules loaded from sentry", ModuleName());
    }
    else
    {
        Log("[%s] Initialize: sentry unavailable - pass-through; starting retry thread",
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
