#include "rule_server.h"
#include "pipe_security.h"
#include "sentry_log.h"
#include "base64.h"
#include "nlohmann/json.hpp"
#include <fstream>
#include <algorithm>
#include <string>

// ── RuleServer ────────────────────────────────────────────────────────────────

RuleServer::RuleServer(std::string rulesPath)
    : m_rulesPath(std::move(rulesPath))
{
    for (auto& h : m_threads) h = INVALID_HANDLE_VALUE;
}

RuleServer::~RuleServer()
{
    if (m_running.load()) Stop();
}

void RuleServer::Start()
{
    InitializeCriticalSection(&m_cacheLock);
    m_running.store(true);
    for (int i = 0; i < kThreadCount; i++)
    {
        DWORD tid = 0;
        m_threads[i] = CreateThread(nullptr, 0, ThreadProc, this, 0, &tid);
        if (m_threads[i] == nullptr || m_threads[i] == INVALID_HANDLE_VALUE)
            SentryLog_Error("RuleServer", "Failed to create thread %d (GLE=%lu)", i, GetLastError());
    }
}

void RuleServer::Stop()
{
    m_running.store(false);

    // Unblock each waiting ConnectNamedPipe with a dummy client connection.
    for (int i = 0; i < kThreadCount; i++)
    {
        HANDLE h = CreateFileW(L"\\\\.\\pipe\\rasp_sentry_rules",
                               GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
    }

    HANDLE valid[kThreadCount];
    int    count = 0;
    for (auto& h : m_threads)
        if (h != INVALID_HANDLE_VALUE) valid[count++] = h;
    if (count > 0)
        WaitForMultipleObjects(count, valid, TRUE, 3000);
    for (auto& h : m_threads)
    {
        if (h != INVALID_HANDLE_VALUE) CloseHandle(h);
        h = INVALID_HANDLE_VALUE;
    }
    DeleteCriticalSection(&m_cacheLock);
}

void RuleServer::InvalidateCache()
{
    SentryLog_Info("RuleServer", "Cache invalidated — next request will rebuild from disk");
    EnterCriticalSection(&m_cacheLock);
    m_cachedAssembled.clear();
    m_cachedAmsiRules.clear();
    LeaveCriticalSection(&m_cacheLock);
}

DWORD WINAPI RuleServer::ThreadProc(LPVOID param)
{
    static_cast<RuleServer*>(param)->ServerLoop();
    return 0;
}

void RuleServer::ServerLoop()
{
    SECURITY_ATTRIBUTES sa = {};
    PACL acl = nullptr;
    bool haveSa = MakeAuthenticatedUsersSecurity(&sa, &acl);

    while (m_running.load())
    {
        HANDLE hPipe = CreateNamedPipeW(
            L"\\\\.\\pipe\\rasp_sentry_rules",
            PIPE_ACCESS_DUPLEX,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            kThreadCount,
            65536,  // outBufSize
            256,    // inBufSize (command is short)
            0,
            haveSa ? &sa : nullptr);

        if (hPipe == INVALID_HANDLE_VALUE)
        {
            SentryLog_Error("RuleServer", "CreateNamedPipeW failed (GLE=%lu)", GetLastError());
            Sleep(100);
            continue;
        }

        BOOL connected = ConnectNamedPipe(hPipe, nullptr);
        if (!m_running.load())
        {
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            break;
        }
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED)
        {
            CloseHandle(hPipe);
            continue;
        }

        // Read the command line (GET_RULES or GET_ALL_RULES)
        char reqBuf[64] = {};
        DWORD bytesRead = 0;
        ReadFile(hPipe, reqBuf, static_cast<DWORD>(sizeof(reqBuf) - 1), &bytesRead, nullptr);
        reqBuf[bytesRead] = '\0';
        std::string req(reqBuf, bytesRead);
        while (!req.empty() && (req.back() == '\n' || req.back() == '\r' || req.back() == ' '))
            req.pop_back();

        const std::string* response = nullptr;
        if (_stricmp(req.c_str(), "GET_ALL_RULES") == 0)
            response = &GetAssembledJson();
        else if (_stricmp(req.c_str(), "GET_RULES") == 0)
            response = &GetAmsiRulesJson();
        else
            SentryLog_Warn("RuleServer", "Unknown command: '%s'", req.c_str());

        if (response && !response->empty())
        {
            std::string resp = *response + "\n";
            DWORD written = 0;
            WriteFile(hPipe, resp.c_str(), static_cast<DWORD>(resp.size()), &written, nullptr);
            FlushFileBuffers(hPipe);
        }

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);
    }

    if (haveSa) FreePipeSecurity(&sa, acl);
}

// ── Cache management ──────────────────────────────────────────────────────────

const std::string& RuleServer::GetAssembledJson()
{
    // Fast path (no lock)
    if (!m_cachedAssembled.empty()) return m_cachedAssembled;

    EnterCriticalSection(&m_cacheLock);
    if (m_cachedAssembled.empty())
    {
        SentryLog_Info("RuleServer", "Cache miss — building assembled JSON");
        m_cachedAssembled = BuildAssembledJson();
    }
    LeaveCriticalSection(&m_cacheLock);
    return m_cachedAssembled;
}

const std::string& RuleServer::GetAmsiRulesJson()
{
    // Ensure assembled is ready first (without holding cacheLock twice)
    GetAssembledJson();

    if (!m_cachedAmsiRules.empty()) return m_cachedAmsiRules;

    EnterCriticalSection(&m_cacheLock);
    if (m_cachedAmsiRules.empty())
    {
        SentryLog_Info("RuleServer", "Cache miss — building AMSI-filtered JSON");
        m_cachedAmsiRules = FilterAmsiProviderRules(m_cachedAssembled);
    }
    LeaveCriticalSection(&m_cacheLock);
    return m_cachedAmsiRules;
}

// ── JSON assembly (static free functions — nlohmann types stay in .cpp) ───────

using json = nlohmann::json;

static std::string DirOf(const std::string& filePath)
{
    size_t pos = filePath.find_last_of("/\\");
    return (pos == std::string::npos) ? "." : filePath.substr(0, pos);
}

// Transformation 1 — replaces regex-based InlineGlobalLibraries() in C# RuleServer.
static void InlineGlobalLibraries(json& root, const std::string& rulesDir)
{
    if (!root.contains("globalLibraries")) return;
    const auto& libs = root["globalLibraries"];
    if (!libs.is_array()) return;

    json b64Array = json::array();
    int count = 0;

    for (const auto& entry : libs)
    {
        if (!entry.is_string()) continue;
        std::string relPath = entry.get<std::string>();
        std::replace(relPath.begin(), relPath.end(), '/', '\\');
        std::string absPath = rulesDir + "\\" + relPath;

        std::ifstream fs(absPath, std::ios::binary);
        if (!fs.is_open())
        {
            SentryLog_Warn("RuleServer", "globalLibrary not found: %s", absPath.c_str());
            continue;
        }
        std::vector<uint8_t> bytes(
            (std::istreambuf_iterator<char>(fs)),
            std::istreambuf_iterator<char>());

        b64Array.push_back(base64_encode(bytes));
        ++count;
    }

    root.erase("globalLibraries");
    root["globalLibrariesBase64"] = std::move(b64Array);
    SentryLog_Info("RuleServer", "Inlined %d global library file(s) as globalLibrariesBase64", count);
}

// Transformation 2 — replaces regex-based InlineScriptFiles() in C# RuleServer.
static void InlineScriptFiles(json& root, const std::string& rulesDir)
{
    if (!root.contains("rules") || !root["rules"].is_array()) return;

    int count = 0;
    for (auto& rule : root["rules"])
    {
        if (!rule.is_object() || !rule.contains("script")) continue;
        if (!rule["script"].is_string()) continue;

        std::string relPath = rule["script"].get<std::string>();
        std::replace(relPath.begin(), relPath.end(), '/', '\\');
        std::string absPath = rulesDir + "\\" + relPath;

        rule.erase("script");

        std::ifstream fs(absPath, std::ios::binary);
        if (!fs.is_open())
        {
            SentryLog_Warn("RuleServer", "Script not found: %s — rule gets empty scriptBodyBase64", absPath.c_str());
            rule["scriptBodyBase64"] = "";
            continue;
        }
        std::vector<uint8_t> bytes(
            (std::istreambuf_iterator<char>(fs)),
            std::istreambuf_iterator<char>());

        rule["scriptBodyBase64"] = base64_encode(bytes);
        ++count;
    }
    SentryLog_Info("RuleServer", "Inlined %d Lua script file(s) as scriptBodyBase64", count);
}

// Transformation 4 — replaces regex ExtractGlobalLibPrefix() in C# RuleServer.
static std::string ExtractGlobalLibPrefix(const json& root)
{
    if (!root.contains("globalLibrariesBase64")) return {};
    const auto& arr = root["globalLibrariesBase64"];
    if (!arr.is_array()) return {};

    std::string prefix;
    for (const auto& entry : arr)
    {
        if (!entry.is_string()) continue;
        std::string decoded = base64_decode_str(entry.get<std::string>());
        if (!decoded.empty())
        {
            prefix += decoded;
            prefix += '\n';
        }
    }
    return prefix;
}

// Transformation 5 — replaces regex PrependLibToRuleScript() in C# RuleServer.
static void PrependLibToRuleScript(json& rule, const std::string& libPrefix)
{
    if (libPrefix.empty()) return;
    if (!rule.contains("scriptBodyBase64")) return;
    if (!rule["scriptBodyBase64"].is_string()) return;

    const std::string existingB64 = rule["scriptBodyBase64"].get<std::string>();
    std::string ruleScript;
    if (!existingB64.empty())
    {
        ruleScript = base64_decode_str(existingB64);
        if (ruleScript.empty()) return;  // corrupt base64 — leave unchanged
    }

    rule["scriptBodyBase64"] = base64_encode(libPrefix + ruleScript);
}

// ── RuleServer JSON methods ───────────────────────────────────────────────────

// Replaces C# BuildAssembledJson() — top-level orchestrator.
std::string RuleServer::BuildAssembledJson()
{
    try
    {
        std::ifstream f(m_rulesPath, std::ios::in);
        if (!f.is_open())
        {
            SentryLog_Error("RuleServer", "Cannot open rules file: %s", m_rulesPath.c_str());
            return "[]";
        }

        json root;
        f >> root;   // throws nlohmann::json::parse_error on malformed input

        std::string rulesDir = DirOf(m_rulesPath);
        ::InlineGlobalLibraries(root, rulesDir);
        ::InlineScriptFiles(root, rulesDir);

        return root.dump();
    }
    catch (const std::exception& ex)
    {
        SentryLog_Error("RuleServer", "BuildAssembledJson failed: %s", ex.what());
        return "[]";
    }
}

// Transformation 3 — replaces manual brace-counting FilterAmsiProviderRules() in C# RuleServer.
std::string RuleServer::FilterAmsiProviderRules(const std::string& assembledJson)
{
    if (assembledJson.empty() || assembledJson == "[]") return "[]";
    try
    {
        json root = json::parse(assembledJson);
        std::string libPrefix = ::ExtractGlobalLibPrefix(root);

        if (!root.contains("rules") || !root["rules"].is_array()) return "[]";

        json result = json::array();
        for (auto rule : root["rules"])  // value copy — mutated per rule
        {
            if (!rule.is_object()) continue;
            if (!rule.contains("sensor") || !rule["sensor"].is_string()) continue;
            if (rule["sensor"].get<std::string>() != "AmsiProvider") continue;

            ::PrependLibToRuleScript(rule, libPrefix);
            result.push_back(std::move(rule));
        }

        SentryLog_Info("RuleServer", "Filtered %zu AmsiProvider rule(s)", result.size());
        return result.dump();
    }
    catch (const std::exception& ex)
    {
        SentryLog_Error("RuleServer", "FilterAmsiProviderRules failed: %s", ex.what());
        return "[]";
    }
}
