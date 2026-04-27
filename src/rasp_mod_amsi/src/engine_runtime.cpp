#include "../include/engine_runtime.h"

#include "../include/amsi_rule_engine.h"

#include <cstdarg>
#include <cstdio>
#include <new>

namespace {

std::unique_ptr<AmsiRuleEngine> DefaultEngineFactory()
{
    return std::unique_ptr<AmsiRuleEngine>(new(std::nothrow) AmsiRuleEngine());
}

bool DefaultEngineInitializer(AmsiRuleEngine& engine)
{
    engine.Initialize();
    return true;
}

} // namespace

const char* EngineStateName(EngineState state)
{
    switch (state) {
    case EngineState::Uninitialized: return "Uninitialized";
    case EngineState::Initializing:  return "Initializing";
    case EngineState::Ready:         return "Ready";
    case EngineState::Reloading:     return "Reloading";
    case EngineState::Stopping:      return "Stopping";
    case EngineState::Inert:         return "Inert";
    case EngineState::Stopped:       return "Stopped";
    case EngineState::Faulted:       return "Faulted";
    default:                         return "Unknown";
    }
}

ScanGuard::ScanGuard(ScanGuard&& other) noexcept
    : m_runtime(other.m_runtime), m_engine(other.m_engine)
{
    other.m_runtime = nullptr;
    other.m_engine = nullptr;
}

ScanGuard& ScanGuard::operator=(ScanGuard&& other) noexcept
{
    if (this != &other) {
        Reset();
        m_runtime = other.m_runtime;
        m_engine = other.m_engine;
        other.m_runtime = nullptr;
        other.m_engine = nullptr;
    }
    return *this;
}

ScanGuard::~ScanGuard()
{
    Reset();
}

void ScanGuard::Reset()
{
    if (m_runtime)
        m_runtime->ReleaseScan();
    m_runtime = nullptr;
    m_engine = nullptr;
}

EngineRuntime::EngineRuntime()
    : EngineRuntime(DefaultEngineFactory, DefaultEngineInitializer)
{
}

EngineRuntime::EngineRuntime(EngineFactory factory, EngineInitializer initializer)
    : m_factory(std::move(factory)), m_initializer(std::move(initializer))
{
}

EngineRuntime::~EngineRuntime()
{
    // Shutdown must be explicit. A static runtime destructor can run while the
    // loader is detaching the DLL, so it must not start threads, take long
    // waits, or invoke engine shutdown paths.
}

bool EngineRuntime::EnsureInitialized()
{
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_state == EngineState::Ready || m_state == EngineState::Reloading)
            return true;
        if (m_state == EngineState::Inert ||
            m_state == EngineState::Stopping ||
            m_state == EngineState::Stopped ||
            m_state == EngineState::Faulted)
            return false;
        if (m_state == EngineState::Initializing)
            return false;
        SetStateLocked(EngineState::Initializing, "ensure_initialized");
    }

    std::unique_ptr<AmsiRuleEngine> engine = m_factory ? m_factory() : nullptr;
    bool ok = engine && (!m_initializer || m_initializer(*engine));

    std::lock_guard<std::mutex> lock(m_mutex);
    if (!ok) {
        SetStateLocked(EngineState::Faulted, "initialize_failed");
        return false;
    }

    m_engine = std::move(engine);
    SetStateLocked(EngineState::Ready, "initialize_success");
    return true;
}

ScanGuard EngineRuntime::TryEnterScan()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if ((m_state != EngineState::Ready && m_state != EngineState::Reloading) || !m_engine) {
        char msg[160];
        snprintf(msg, sizeof(msg),
                 "[RaspAmsi] telemetry scan_enter_rejected state=%s active=%ld\n",
                 EngineStateName(m_state), m_activeScans.load());
        OutputDebugStringA(msg);
        return {};
    }

    ++m_activeScans;
    return ScanGuard(this, m_engine.get());
}

bool EngineRuntime::BeginShutdown(const char* reason, DWORD drainTimeoutMs)
{
    AmsiRuleEngine* engine = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_state == EngineState::Stopped || m_state == EngineState::Inert)
            return m_activeScans.load() == 0;
        SetStateLocked(EngineState::Stopping, reason ? reason : "shutdown");
        engine = m_engine.get();
    }

    bool drained = WaitForActiveScansToDrain(drainTimeoutMs);
    if (!drained) {
        Log("[RaspAmsi] telemetry shutdown_drain_timeout active=%ld", ActiveScanCount());
        EnterInert("shutdown_drain_timeout");
        return false;
    }

    if (engine)
        engine->Shutdown();
    EnterInert(reason ? reason : "shutdown_complete");
    return true;
}

bool EngineRuntime::WaitForActiveScansToDrain(DWORD timeoutMs)
{
    std::unique_lock<std::mutex> lock(m_mutex);
    if (timeoutMs == 0)
        return m_activeScans.load() == 0;
    return m_scanDrained.wait_for(
        lock,
        std::chrono::milliseconds(timeoutMs),
        [this]() { return m_activeScans.load() == 0; });
}

void EngineRuntime::EnterInert(const char* reason)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_state != EngineState::Stopped)
        SetStateLocked(EngineState::Inert, reason ? reason : "enter_inert");
}

bool EngineRuntime::TryBeginReload()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_state != EngineState::Ready)
        return false;
    SetStateLocked(EngineState::Reloading, "reload_begin");
    return true;
}

void EngineRuntime::EndReload(bool success)
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_state == EngineState::Reloading)
        SetStateLocked(success ? EngineState::Ready : EngineState::Faulted,
                       success ? "reload_success" : "reload_failed");
}

EngineState EngineRuntime::GetState() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_state;
}

void EngineRuntime::Log(const char* fmt, ...) const
{
    AmsiRuleEngine* engine = nullptr;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        engine = m_engine.get();
    }
    if (!engine)
        return;

    char buf[1024];
    va_list va;
    va_start(va, fmt);
    vsnprintf(buf, sizeof(buf), fmt, va);
    va_end(va);
    engine->Log("%s", buf);
}

void EngineRuntime::ReleaseScan()
{
    long remaining = --m_activeScans;
    if (remaining <= 0)
        m_scanDrained.notify_all();
}

void EngineRuntime::SetStateLocked(EngineState next, const char* reason)
{
    if (m_state == next)
        return;

    EngineState old = m_state;
    m_state = next;

    char msg[256];
    snprintf(msg, sizeof(msg),
             "[RaspAmsi] telemetry state_transition old=%s new=%s reason=%s active=%ld\n",
             EngineStateName(old), EngineStateName(next),
             reason ? reason : "", m_activeScans.load());
    OutputDebugStringA(msg);
}

EngineRuntime& GetAmsiEngineRuntime()
{
    static EngineRuntime runtime;
    return runtime;
}
