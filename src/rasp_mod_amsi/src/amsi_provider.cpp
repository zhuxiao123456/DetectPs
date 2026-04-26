// =========================================================================
// amsi_provider.cpp — IAntimalwareProvider implementation
// 整个模块的“哨兵”，负责从 Windows AMSI 接口读取恶意脚本内容
// =========================================================================

#include <new>

#include "../include/rasp_mod_amsi.h"
#include "../include/amsi_rule_engine.h"

// ── Host process name helper ──────────────────────────────────────────────
// Returns just the EXE filename of the current process (no path, no extension
// stripping) — used in load/unload log lines for quick triage in DebugView.

static void LogHostProcess(const char *event) {
    char path[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, path, MAX_PATH);

    // Walk to last backslash to get bare filename
    const char *name = path;
    for (const char *p = path; *p; ++p)
        if (*p == '\\' || *p == '/') name = p + 1;

    char pid[16];
    sprintf_s(pid, "%lu", GetCurrentProcessId());

    char msg[512];
    sprintf_s(msg, "[AMSI] %s — process: %s  pid: %s\n", event, name, pid);
    OutputDebugStringA(msg);

    if (g_engine) g_engine->Log("[RaspAmsi] %s — process=%s pid=%s", event, name, pid);
}

// ── CRaspAmsiProvider ─────────────────────────────────────────────────────

long g_serverLocks(0);  // COM服务器锁计数
// 初始化为1，- 服务器锁：跟踪活动实例数量- 线程安全：使用Interlocked操作

CRaspAmsiProvider::CRaspAmsiProvider() : _refCount(1) {
    InterlockedIncrement(&g_serverLocks);
    LogHostProcess("provider loaded into");
}

CRaspAmsiProvider::~CRaspAmsiProvider() {
    InterlockedDecrement(&g_serverLocks);
    LogHostProcess("provider unloading from");
}

/*
- 功能：COM接口查询
- 支持的接口：IUnknown、IAntimalwareProvider
- 返回：S_OK或E_NOINTERFACE
*/
IFACEMETHODIMP CRaspAmsiProvider::QueryInterface(REFIID riid, void **ppv) {
    if (riid == IID_IUnknown || riid == __uuidof(IAntimalwareProvider)) {
        OutputDebugStringA("[AMSI:QueryInterface] - Interface Created.");
        *ppv = static_cast<IAntimalwareProvider *>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

/*
- 功能：引用计数管理
- 线程安全：原子操作
- 内存管理：引用计数为0时自删除
*/
IFACEMETHODIMP_(ULONG)

CRaspAmsiProvider::AddRef() { return InterlockedIncrement(&_refCount); }

IFACEMETHODIMP_(ULONG)

CRaspAmsiProvider::Release() {
    LONG r = InterlockedDecrement(&_refCount);
    if (r == 0)
        delete this;
    return r;
}

// ── IAntimalwareProvider ──────────────────────────────────────────────
/*
核心扫描函数
目的：接收执行引擎（如 PowerShell 解释器）传递过来的脚本缓冲区，决定是否拦截
*/
IFACEMETHODIMP CRaspAmsiProvider::Scan(IAmsiStream *stream, AMSI_RESULT *result) {
    OutputDebugStringA("[AMSI:Scan] Scanning Script\n");

    *result = AMSI_RESULT_NOT_DETECTED; // fail-open default

    if (g_unloadInProgress.load()) {
        OutputDebugStringA("[AMSI:Scan] unload in progress — pass-through\n");
        return S_OK;
    }

    if (!g_engine || !stream) {
        OutputDebugStringA("[AMSI:Scan] Engine / Stream not ready\n");
        return S_OK;
    }

    // ── 扫描内容名称（文件路径或脚本标识） ──────────────────────────────────────────
    wchar_t contentName[512] = {};
    ULONG cbOut = 0;
    stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_NAME,
                         (ULONG)
    sizeof(contentName), (PBYTE) contentName, &cbOut);

    // ── 获取应用名称 ──────────────────────────────────────────────
    wchar_t appName[256] = {};
    stream->GetAttribute(AMSI_ATTRIBUTE_APP_NAME,
                         (ULONG)
    sizeof(appName), (PBYTE) appName, &cbOut);

    // ── Extract content size ──────────────────────────────────────────
    ULONGLONG contentSize = 0;
    cbOut = sizeof(contentSize);
    stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE,
                         (ULONG)
    sizeof(contentSize), (PBYTE) & contentSize, &cbOut);

    // ── Read content sample ───────────────────────────────────────────
    // Primary: AMSI_ATTRIBUTE_CONTENT_ADDRESS — 指向内存缓冲区的直接指针. PowerShell passes inline script content this way;
    // IAmsiStream::Read() returns 0 for these streams because the data is not presented as a seekable byte stream.
    // Fallback: stream->Read() for streaming / file-backed AMSI content.
    char sample[1024] = {};
    ULONG sampleRead = 0;

    PVOID contentAddr = nullptr;
    ULONG addrOut = 0;
    // 优先使用 AMSI_ATTRIBUTE_CONTENT_ADDRESS（Powershell内联脚本） 直接读取内存指针（针对 inline 脚本）
    if (SUCCEEDED(stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_ADDRESS,
                                       (ULONG)
        sizeof(contentAddr),
                (PBYTE) & contentAddr, &addrOut))
    && contentAddr != nullptr && contentSize > 0)
    {
        ULONG
                toCopy = (ULONG)
        min(contentSize, (ULONGLONG)(sizeof(sample) - 1));
        memcpy(sample, contentAddr, toCopy);
        sampleRead = toCopy;
        OutputDebugStringA("[AMSI:Scan] content via CONTENT_ADDRESS\n");
    }
    else
    {
        // 如果失败，使用 stream->Read() 读取流
        HRESULT
                hrRead = stream->Read(0, (ULONG)
        sizeof(sample) - 1,
                (unsigned char *) sample, &sampleRead);
        char dbgRead[128];
        sprintf_s(dbgRead, "[AMSI:Scan] content via Read hr=0x%08X read=%lu\n",
                  (unsigned) hrRead, sampleRead);
        OutputDebugStringA(dbgRead);
    }
    if (sampleRead < (ULONG)sizeof(sample))
    sample[sampleRead] = '\0';

    /*
        PowerShell 传给 AMSI 的通常是宽字符 (UTF-16LE)。
        代码通过检查 BOM (0xFF 0xFE) 或检查前 16 个字节的奇数位是否为 0 (nullsAtOdd >= 3) 来判定宽字符，
        并强制使用 WideCharToMultiByte 降维到 UTF-8，以便后续 Lua 的字符串正则 (string.find) 能正常工作
        Mark: 宽字符检测依赖于 nullsAtOdd >= 3,攻击者可以在开头 16 个字节内故意使用大量特殊的 ASCII 控制字符或特定 Unicode 字符，导致奇数位不为 0
    */
    const char *evalSample = sample;
    ULONG evalLen = sampleRead;
    char narrowBuf[1024] = {};

    if (sampleRead >= 4) {
        bool hasBom = ((unsigned char) sample[0] == 0xFF &&
                       (unsigned char) sample[1] == 0xFE);
        bool likelyWide = hasBom;
        if (!likelyWide) {
            int nullsAtOdd = 0;
            ULONG
                    check = min(sampleRead, (ULONG)
            16);
            // 判断前 16 个字节的奇数位是否为 0
            for (ULONG k = 1; k < check; k += 2)
                if ((unsigned char) sample[k] == 0) nullsAtOdd++;
            likelyWide = (nullsAtOdd >= 3);
        }
        // 转换为utf-8,Mark: 添加一个转换失败的错误处理
        if (likelyWide) {
            const wchar_t *wptr = reinterpret_cast<const wchar_t *>(
                    hasBom ? sample + 2 : sample);
            int wlen = (int) ((sampleRead - (hasBom ? 2u : 0u)) / sizeof(wchar_t));
            int nb = WideCharToMultiByte(CP_UTF8, 0, wptr, wlen,
                                         narrowBuf, (int) sizeof(narrowBuf) - 1,
                                         nullptr, nullptr);
            if (nb > 0) {
                narrowBuf[nb] = '\0';
                evalSample = narrowBuf;
                evalLen = (ULONG)
                nb;
                OutputDebugStringA("[AMSI:Scan] UTF-16LE detected — narrowed for Lua patterns\n");
            }
        }
    }

    {
        char dbgSize[256];
        sprintf_s(dbgSize, "[AMSI:Scan] contentSize=%llu sampleRead=%lu evalLen=%lu\n",
                  contentSize, sampleRead, evalLen);
        OutputDebugStringA(dbgSize);
    }

    // ── Evaluate rules in-process ─────────────────────────────────────
    AmsiEvalResult eval = g_engine->Evaluate(
            contentName, appName, evalSample, evalLen);

    // ── Return blocking decision ──────────────────────────────────────
    // Detection event is sent inside g_engine->Evaluate() via SendDetectionEvent().
    if (eval.ruleMatched)
        OutputDebugStringA("[AMSI:Scan] rule matched — event already sent by engine\n");
    if (eval.block) {
        OutputDebugStringA("AMSI - script blocked");
        *result = AMSI_RESULT_DETECTED;
    }

    return S_OK;
}

void STDMETHODCALLTYPE
CRaspAmsiProvider::CloseSession(ULONGLONG /*session*/)
        {
                // 关闭会话(空实现、amsi无会话状态)
        }

/*
- 功能：返回提供者显示名称
- 返回值：L"RaspAmsiProvider"
- 内存管理：使用CoTaskMemAlloc
*/
IFACEMETHODIMP CRaspAmsiProvider::DisplayName(LPWSTR *displayName) {
    if (!displayName)
        return E_POINTER;
    static const wchar_t kName[] = L"RaspAmsiProvider";
    *displayName = (LPWSTR) CoTaskMemAlloc((wcslen(kName) + 1) * sizeof(wchar_t));
    if (!*displayName)
        return E_OUTOFMEMORY;
    wcscpy_s(*displayName, ARRAYSIZE(kName), kName);
    return S_OK;
}

// ── CRaspAmsiProviderFactory ──────────────────────────────────────────────
/*
 * Windows 系统本身不会直接去 new 你的 CRaspAmsiProvider，而是先找这个工厂要一个 IClassFactory 接口，
 * 然后命令工厂：“给我生产一个 AMSI 拦截器实例”。
 * */
class CRaspAmsiProviderFactory : public IClassFactory {
public:
    STDMETHODIMP QueryInterface(REFIID riid, void **ppv) override {
        if (riid == IID_IUnknown || riid == IID_IClassFactory) {
            *ppv = static_cast<IClassFactory *>(this);
            AddRef();
            return S_OK;
        }
        *ppv = nullptr;
        return E_NOINTERFACE;
    }

    // 下面的两个操作，使得引用计数永远不会为0，防止delete this的崩溃
    STDMETHODIMP_(ULONG)

    AddRef() override { return 2; } // static lifetime
    STDMETHODIMP_(ULONG)

    Release() override { return 1; }

    STDMETHODIMP CreateInstance(IUnknown *pOuter, REFIID riid, void **ppv) override {
        // 建议把 RASP 引擎的初始化（g_engine->Initialize()）放在 CRaspAmsiProvider::Scan 方法里，用 std::call_once 保护
        if (pOuter)
            return CLASS_E_NOAGGREGATION;  // 防聚合攻击
        CRaspAmsiProvider *p = new(std::nothrow) CRaspAmsiProvider();  // nothrow 保证了内存不足时只会优雅地返回 E_OUTOFMEMORY
        if (!p)
            return E_OUTOFMEMORY;
        HRESULT hr = p->QueryInterface(riid, ppv);
        p->Release();
        return hr;
    }

    STDMETHODIMP LockServer(BOOL lock) override {
        if (lock)
            InterlockedIncrement(&g_serverLocks);
        else
            InterlockedDecrement(&g_serverLocks);
        return S_OK;
    }
};

// ── COM exports ───────────────────────────────────────────────────────────
/*
 * 功能: COM 载入动态链接库（DLL）后的第一个正式“握手”点,Windows 的 AMSI 管理器（客户端）在通过注册表找到你的 DLL 后，
 * 会调用此函数来获取“类工厂”（Class Factory），进而通过工厂创建真正的拦截实例 CRaspAmsiProvider
 * */
STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv) {
    if (rclsid != CLSID_RaspAmsiProvider)
        return CLASS_E_CLASSNOTAVAILABLE;  // 身份验证
    static CRaspAmsiProviderFactory g_factory;
    return g_factory.QueryInterface(riid, ppv);
}

/*
 * 崩溃链条模拟：
    PowerShell 执行完了一个脚本。
    最后一个 CRaspAmsiProvider 对象被释放，g_serverLocks 归零。
    PowerShell 决定清理内存，调用 DllCanUnloadNow()，你的代码返回了 S_OK。
    致命瞬间：操作系统立刻执行 FreeLibrary 卸载你的 DLL 内存。但是，你的 g_engine 里面的后台线程还在运行（例如正阻塞在读取 IPC 管道上）！
    当后台线程醒来，准备执行下一条汇编指令时，它所在的内存页已经被 OS 标为空白（Unmapped）。
    结果：0xC0000005 Access Violation（内存访问越界），整个 PowerShell.exe 瞬间闪退崩溃！
方案1：无论系统怎么问，永远拒绝卸载，直到整个宿主进程自然退出，由操作系统统一回收所有内存和线程(缺点：在宿主进程的生命周期内会一直占用几 MB 的内存)
 * */
STDAPI DllCanUnloadNow() { return g_serverLocks == 0 ? S_OK : S_FALSE; }
