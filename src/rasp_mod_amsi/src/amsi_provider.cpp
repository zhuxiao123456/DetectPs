// =========================================================================
// amsi_provider.cpp - IAntimalwareProvider implementation
// =========================================================================

#include <new>
#include <memory>
#include <cstring>
#include <vector>

#include "../include/rasp_mod_amsi.h"
#include "../include/amsi_rule_engine.h"
#include "../include/engine_runtime.h"
#include "../include/process_context_provider.h"
#include "../include/scan_context.h"


long g_serverLocks(0);

namespace {

template <size_t N>
void NullTerminateAmsiWideAttribute(wchar_t (&buffer)[N], ULONG bytesWritten)
{
    if (N == 0)
        return;

    size_t charsWritten = static_cast<size_t>(bytesWritten / sizeof(wchar_t));
    if (charsWritten >= N)
        charsWritten = N - 1;
    buffer[charsWritten] = L'\0';
    buffer[N - 1] = L'\0';
}

bool SafeCopyAmsiContentAddress(void* dst, const void* src, size_t bytes)
{
    if (!dst || !src || bytes == 0)
        return false;

    __try {
        std::memcpy(dst, src, bytes);
        return true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

} // namespace

CRaspAmsiProvider::CRaspAmsiProvider() : _refCount(1) {
    InterlockedIncrement(&g_serverLocks);
}

CRaspAmsiProvider::~CRaspAmsiProvider() {
    InterlockedDecrement(&g_serverLocks);
}

IFACEMETHODIMP CRaspAmsiProvider::QueryInterface(REFIID riid, void **ppv) {
    if (riid == IID_IUnknown || riid == __uuidof(IAntimalwareProvider)) {
        *ppv = static_cast<IAntimalwareProvider *>(this);
        AddRef();
        return S_OK;
    }
    *ppv = nullptr;
    return E_NOINTERFACE;
}

IFACEMETHODIMP_(ULONG) CRaspAmsiProvider::AddRef() { return InterlockedIncrement(&_refCount); }

IFACEMETHODIMP_(ULONG) CRaspAmsiProvider::Release() {
    LONG r = InterlockedDecrement(&_refCount);
    if (r == 0)
        delete this;
    return r;
}

IFACEMETHODIMP CRaspAmsiProvider::Scan(IAmsiStream *stream, AMSI_RESULT *result) {
    if (!result)
        return E_POINTER;

    *result = AMSI_RESULT_NOT_DETECTED;

    if (!stream) {
        GetAmsiEngineRuntime().LogWithSeverity(RaspDiagSeverity::Warning,
                                               "[AMSI:Scan] Stream not ready");
        return S_OK;
    }

    EngineRuntime& runtime = GetAmsiEngineRuntime();
    if (!runtime.EnsureInitialized()) {
        return S_OK;
    }

    ScanGuard scan = runtime.TryEnterScan();
    if (!scan.IsActive() || !scan.Engine()) {
        runtime.LogWithSeverity(RaspDiagSeverity::Debug,
                                "[AMSI:Scan] runtime rejected scan - pass-through");
        return S_OK;
    }

    AmsiRuleEngine* engine = scan.Engine();

    wchar_t contentName[512] = {};
    ULONG cbOut = 0;
    if (SUCCEEDED(stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_NAME,
                                       static_cast<ULONG>(sizeof(contentName)),
                                       reinterpret_cast<PBYTE>(contentName), &cbOut))) {
        NullTerminateAmsiWideAttribute(contentName, cbOut);
    }

    wchar_t appName[256] = {};
    cbOut = 0;
    if (SUCCEEDED(stream->GetAttribute(AMSI_ATTRIBUTE_APP_NAME,
                                       static_cast<ULONG>(sizeof(appName)),
                                       reinterpret_cast<PBYTE>(appName), &cbOut))) {
        NullTerminateAmsiWideAttribute(appName, cbOut);
    }

    ULONGLONG contentSize = 0;
    cbOut = sizeof(contentSize);
    stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_SIZE,
                         static_cast<ULONG>(sizeof(contentSize)),
                         reinterpret_cast<PBYTE>(&contentSize), &cbOut);

    static constexpr ULONG kMaxAmsiReadBytes = kMaxMaxScanContentBytes;
    std::vector<char> sample(kMaxAmsiReadBytes + 1, '\0');
    ULONG sampleRead = 0;

    PVOID contentAddr = nullptr;
    ULONG addrOut = 0;
    bool copiedFromAddress = false;
    if (SUCCEEDED(stream->GetAttribute(AMSI_ATTRIBUTE_CONTENT_ADDRESS,
                                       static_cast<ULONG>(sizeof(contentAddr)),
                                       reinterpret_cast<PBYTE>(&contentAddr), &addrOut)) &&
        contentAddr != nullptr && contentSize > 0) {
        ULONG toCopy = static_cast<ULONG>(min(contentSize, static_cast<ULONGLONG>(sample.size() - 1)));
        if (SafeCopyAmsiContentAddress(sample.data(), contentAddr, toCopy)) {
            sampleRead = toCopy;
            copiedFromAddress = true;
        } else {
            runtime.LogWithSeverity(RaspDiagSeverity::Warning,
                                    "[AMSI:Scan] content address copy failed - falling back to Read");
        }
    }

    if (!copiedFromAddress) {
        HRESULT hrRead = stream->Read(0, static_cast<ULONG>(sample.size() - 1),
                                      reinterpret_cast<unsigned char *>(sample.data()), &sampleRead);
        runtime.LogWithSeverity(RaspDiagSeverity::Debug,
                                "[AMSI:Scan] content via Read hr=0x%08X read=%lu",
                                static_cast<unsigned>(hrRead), sampleRead);
    }

    if (sampleRead < static_cast<ULONG>(sample.size()))
        sample[sampleRead] = '\0';

    const char *evalSample = sample.data();
    ULONG evalLen = sampleRead;
    std::unique_ptr<std::vector<char>> narrowBuf;

    if (sampleRead >= 4) {
        bool hasBom = (static_cast<unsigned char>(sample[0]) == 0xFF &&
                       static_cast<unsigned char>(sample[1]) == 0xFE);
        bool likelyWide = hasBom;
        if (!likelyWide) {
            int nullsAtOdd = 0;
            ULONG check = min(sampleRead, static_cast<ULONG>(16));
            for (ULONG k = 1; k < check; k += 2)
                if (static_cast<unsigned char>(sample[k]) == 0)
                    nullsAtOdd++;
            likelyWide = (nullsAtOdd >= 3);
        }

        if (likelyWide) {
            narrowBuf.reset(new(std::nothrow) std::vector<char>(kMaxAmsiReadBytes + 1, '\0'));
            if (!narrowBuf) {
                runtime.LogWithSeverity(RaspDiagSeverity::Warning,
                                        "[AMSI:Scan] UTF-16 conversion buffer allocation failed");
            } else {
                const wchar_t *wptr = reinterpret_cast<const wchar_t *>(hasBom ? sample.data() + 2 : sample.data());
                int wlen = static_cast<int>((sampleRead - (hasBom ? 2u : 0u)) / sizeof(wchar_t));
                int nb = WideCharToMultiByte(CP_UTF8, 0, wptr, wlen,
                                             narrowBuf->data(), static_cast<int>(narrowBuf->size() - 1),
                                             nullptr, nullptr);
                if (nb > 0) {
                    (*narrowBuf)[nb] = '\0';
                    evalSample = narrowBuf->data();
                    evalLen = static_cast<ULONG>(nb);
                }
            }
        }
    }

    auto processSnapshot = GetProcessContextProvider().GetSnapshot();
    ScanContext scanContext;
    scanContext.processSnapshot = processSnapshot;
    scanContext.process = processSnapshot.get();
    scanContext.emitProcessPathFields = false;

    AmsiEvalResult eval = engine->Evaluate(contentName, appName, evalSample, evalLen, scanContext);
    if (eval.block)
        *result = AMSI_RESULT_DETECTED;

    return S_OK;
}

void STDMETHODCALLTYPE CRaspAmsiProvider::CloseSession(ULONGLONG /*session*/) {
}

IFACEMETHODIMP CRaspAmsiProvider::DisplayName(LPWSTR *displayName) {
    if (!displayName)
        return E_POINTER;
    static const wchar_t kName[] = L"RaspAmsiProvider";
    *displayName = static_cast<LPWSTR>(CoTaskMemAlloc((wcslen(kName) + 1) * sizeof(wchar_t)));
    if (!*displayName)
        return E_OUTOFMEMORY;
    wcscpy_s(*displayName, ARRAYSIZE(kName), kName);
    return S_OK;
}

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

    STDMETHODIMP_(ULONG) AddRef() override { return 2; }
    STDMETHODIMP_(ULONG) Release() override { return 1; }

    STDMETHODIMP CreateInstance(IUnknown *pOuter, REFIID riid, void **ppv) override {
        GetAmsiEngineRuntime().EnsureInitialized();
        if (pOuter)
            return CLASS_E_NOAGGREGATION;
        CRaspAmsiProvider *p = new(std::nothrow) CRaspAmsiProvider();
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

STDAPI DllGetClassObject(REFCLSID rclsid, REFIID riid, LPVOID *ppv) {
    if (rclsid != CLSID_RaspAmsiProvider)
        return CLASS_E_CLASSNOTAVAILABLE;
    static CRaspAmsiProviderFactory g_factory;
    return g_factory.QueryInterface(riid, ppv);
}

STDAPI DllCanUnloadNow() {
    if (RaspSentryBase::AnyHostLivenessThreadRunning())
        return S_FALSE;
    return S_FALSE;
}
