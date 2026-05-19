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

ReloadGuard::ReloadGuard(ReloadGuard&& other) noexcept
    : m_runtime(other.m_runtime),
      m_reason(other.m_reason),
      m_completed(other.m_completed)
{
    other.m_runtime = nullptr;
    other.m_reason = nullptr;
    other.m_completed = true;
}

ReloadGuard::~ReloadGuard()
{
    Reset(false, "guard_destructor");
}

void ReloadGuard::Complete(bool success, const char* detail)
{
    Reset(success, detail);
}

void ReloadGuard::Reset(bool success, const char* detail)
{
    if (m_runtime && !m_completed)
        m_runtime->CompleteReload(success, m_reason, detail);
    m_runtime = nullptr;
    m_reason = nullptr;
    m_completed = true;
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
    bool rejected = false;
    EngineState rejectedState = EngineState::Uninitialized;
    long active = 0;
    const bool pausedAtEntry = m_detectionPaused.load(std::memory_order_relaxed);
    std::lock_guard<std::mutex> lock(m_mutex);
    // Pause/resume is an entry gate: scans that already hold a guard continue;
    // the next scan entrance observes the pause bit and returns NoMatch upstream.
    if (pausedAtEntry ||
        (m_state != EngineState::Ready && m_state != EngineState::Reloading) || !m_engine) {
        rejected = true;
        rejectedState = m_state;
        active = m_activeScans.load();
    }

    if (rejected) {
        DWORD now = GetTickCount();
        DWORD last = m_lastScanRejectTelemetryTick.load();
        bool emit = last == 0 || (now - last) >= 1000;
        if (emit && m_lastScanRejectTelemetryTick.compare_exchange_strong(last, now)) {
            uint64_t suppressed = m_suppressedScanRejectTelemetry.exchange(0);
            char msg[320];
            snprintf(msg, sizeof(msg),
                     "[RaspAmsi] telemetry event=scan_enter_rejected state=%s detail=%s active=%ld suppressed=%llu tid=%lu\n",
                     EngineStateName(rejectedState), EngineStateName(rejectedState),
                     active, static_cast<unsigned long long>(suppressed), GetCurrentThreadId());
            OutputDebugStringA(msg);
        } else {
            m_suppressedScanRejectTelemetry.fetch_add(1);
        }
        return {};
    }
    ++m_activeScans;
    return ScanGuard(this, m_engine.get());
}

void EngineRuntime::PauseDetection()
{
    m_detectionPaused.store(true, std::memory_order_relaxed);
    EmitTelemetry("detection_paused", "pause_detection_signal");
}

void EngineRuntime::ResumeDetection()
{
    m_detectionPaused.store(false, std::memory_order_relaxed);
    EmitTelemetry("detection_resumed", "resume_detection_signal");
}

bool EngineRuntime::IsDetectionPaused() const
{
    return m_detectionPaused.load(std::memory_order_relaxed);
}

bool EngineRuntime::CanAttemptReload() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_state == EngineState::Ready && m_engine != nullptr;
}

ReloadGuard EngineRuntime::TryEnterReload(const char* reason)
{
    EngineState rejectedState = EngineState::Uninitialized;
    bool entered = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_state != EngineState::Ready || !m_engine) {
            rejectedState = m_state;
        } else {
            SetStateLocked(EngineState::Reloading, reason ? reason : "reload_begin");
            entered = true;
        }
    }
    if (entered) {
        EmitTelemetry("reload_begin", reason ? reason : "reload_begin");
        return ReloadGuard(this, reason ? reason : "reload");
    }

    char msg[256];
    snprintf(msg, sizeof(msg),
             "[RaspAmsi] telemetry event=reload_rejected state=%s detail=%s active=%ld tid=%lu\n",
             EngineStateName(rejectedState), EngineStateName(rejectedState),
             ActiveScanCount(), GetCurrentThreadId());
    OutputDebugStringA(msg);
    return {};
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
    EmitTelemetry("shutdown_begin", reason ? reason : "shutdown");

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
    bool changed = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_state != EngineState::Stopped) {
            SetStateLocked(EngineState::Inert, reason ? reason : "enter_inert");
            changed = true;
        }
    }
    if (changed)
        EmitTelemetry("enter_inert", reason ? reason : "enter_inert");
}

void EngineRuntime::EnterFaulted(const char* reason)
{
    bool changed = false;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_state != EngineState::Stopped && m_state != EngineState::Inert) {
            SetStateLocked(EngineState::Faulted, reason ? reason : "faulted");
            changed = true;
        }
    }
    if (changed)
        EmitTelemetry("faulted", reason ? reason : "faulted");
}

void EngineRuntime::EmitTelemetry(const char* event, const char* detail) const
{
    EngineState state;
    long active;
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        state = m_state;
        active = m_activeScans.load();
    }

    char msg[256];
    snprintf(msg, sizeof(msg),
             "[RaspAmsi] telemetry event=%s state=%s detail=%s active=%ld tid=%lu\n",
             event ? event : "", EngineStateName(state), detail ? detail : "",
             active, GetCurrentThreadId());
    OutputDebugStringA(msg);
}

bool EngineRuntime::TryBeginReload()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_state != EngineState::Ready || !m_engine)
        return false;
    SetStateLocked(EngineState::Reloading, "reload_begin");
    return true;
}

void EngineRuntime::EndReload(bool success)
{
    CompleteReload(success, "legacy_end_reload", success ? "success" : "failed");
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
    if (remaining < 0) {
        m_activeScans.store(0);
        EnterFaulted("active_scan_count_underflow");
        remaining = 0;
    }
    if (remaining <= 0)
        m_scanDrained.notify_all();
}

void EngineRuntime::CompleteReload(bool success, const char* reason, const char* detail)
{
    bool ignored = false;
    const char* event = success ? "reload_success" : "reload_failed";
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_state != EngineState::Reloading) {
            ignored = true;
        } else {
            SetStateLocked(EngineState::Ready, success ? "reload_success" : "reload_failed");
        }
    }

    if (ignored)
        EmitTelemetry("reload_complete_ignored", detail ? detail : (reason ? reason : ""));
    else
        EmitTelemetry(event, detail ? detail : (reason ? reason : ""));
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
