#include "process_context_provider.h"

#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition)
        std::cerr << "FAIL: " << message << "\n";
    return condition;
}

class FakeProcessContextPlatform final : public IProcessContextPlatform {
public:
    uint32_t currentPid = 4242;
    std::wstring currentPath = L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
    bool currentPathOk = true;
    uint32_t parentPid = 100;
    ParentPidQueryResult parentPidResult = ParentPidQueryResult::Success;
    uint32_t parentPidError = 0;
    std::wstring parentPath = L"C:\\Windows\\System32\\cmd.exe";
    ProcessPathQueryResult parentPathResult = ProcessPathQueryResult::Success;
    uint32_t parentPathError = 0;
    uint64_t tick = 1000;
    bool delayParentPid = false;
    std::atomic<bool> enteredParentPid{false};

    int captureCurrentCalls = 0;
    int queryParentPidCalls = 0;
    int queryParentPathCalls = 0;

    uint32_t GetCurrentPid() override
    {
        return currentPid;
    }

    bool GetCurrentProcessPath(std::wstring& path, uint32_t& error) override
    {
        ++captureCurrentCalls;
        if (!currentPathOk) {
            error = 5;
            path.clear();
            return false;
        }
        error = 0;
        path = currentPath;
        return true;
    }

    ParentPidQueryResult QueryParentPid(uint32_t& pid, uint32_t& error) override
    {
        ++queryParentPidCalls;
        enteredParentPid.store(true, std::memory_order_release);
        if (delayParentPid)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (parentPidResult != ParentPidQueryResult::Success) {
            error = parentPidError;
            pid = 0;
            return parentPidResult;
        }
        error = 0;
        pid = parentPid;
        return ParentPidQueryResult::Success;
    }

    ProcessPathQueryResult QueryProcessPath(uint32_t pid, std::wstring& path, uint32_t& error) override
    {
        ++queryParentPathCalls;
        if (pid == 4) {
            error = 0;
            path.clear();
            return ProcessPathQueryResult::InternalError;
        }
        if (parentPathResult != ProcessPathQueryResult::Success) {
            error = parentPathError;
            path.clear();
            return parentPathResult;
        }
        error = 0;
        path = parentPath;
        return ProcessPathQueryResult::Success;
    }

    uint64_t MonotonicTickMs() override
    {
        return tick;
    }
};

bool TestSuccessSnapshotIsImmutable()
{
    FakeProcessContextPlatform fake;
    ProcessContextProvider provider(fake);

    const auto& first = provider.GetSnapshot();
    if (!Expect(first.valid, "success snapshot is valid"))
        return false;
    if (!Expect(first.parentResolved, "success snapshot resolves parent"))
        return false;
    if (!Expect(first.status == ProcessCaptureStatus::Success, "success status"))
        return false;
    if (!Expect(first.currentPid == 4242, "current pid captured"))
        return false;
    if (!Expect(first.currentProcessName == "powershell.exe", "current basename preserved"))
        return false;
    if (!Expect(first.parentPid == 100, "parent pid captured"))
        return false;
    if (!Expect(first.parentProcessName == "cmd.exe", "parent basename preserved"))
        return false;

    fake.parentPid = 200;
    fake.parentPath = L"C:\\Windows\\System32\\wscript.exe";
    const auto& second = provider.GetSnapshot();
    if (!Expect(&first == &second, "successful snapshot reference is stable"))
        return false;
    if (!Expect(second.parentPid == 100, "successful snapshot is not refreshed"))
        return false;
    return Expect(fake.queryParentPidCalls == 1, "success path captures parent once");
}

bool TestParentOpenDeniedKeepsValidSnapshot()
{
    FakeProcessContextPlatform fake;
    fake.parentPathResult = ProcessPathQueryResult::AccessDenied;
    fake.parentPathError = 5;

    ProcessContextProvider provider(fake);
    const auto& snapshot = provider.GetSnapshot();
    if (!Expect(snapshot.valid, "current process context remains valid when parent open is denied"))
        return false;
    if (!Expect(!snapshot.parentResolved, "parent is unresolved on access denied"))
        return false;
    if (!Expect(snapshot.status == ProcessCaptureStatus::ParentOpenDenied, "access denied status"))
        return false;
    if (!Expect(snapshot.parentPid == fake.parentPid, "parent pid retained on access denied"))
        return false;
    return Expect(snapshot.parentProcessName.empty(), "unavailable parent name is empty string");
}

bool TestParentProcessExitedStatus()
{
    FakeProcessContextPlatform fake;
    fake.parentPathResult = ProcessPathQueryResult::ProcessExited;
    fake.parentPathError = 87;

    ProcessContextProvider provider(fake);
    const auto& snapshot = provider.GetSnapshot();
    return Expect(snapshot.status == ProcessCaptureStatus::ParentProcessExited,
                  "invalid parameter maps to parent process exited");
}

bool TestParentSystemStatus()
{
    FakeProcessContextPlatform fake;
    fake.parentPid = 4;

    ProcessContextProvider provider(fake);
    const auto& snapshot = provider.GetSnapshot();
    if (!Expect(snapshot.valid, "system parent snapshot is valid"))
        return false;
    if (!Expect(snapshot.parentResolved, "system parent is resolved"))
        return false;
    if (!Expect(snapshot.status == ProcessCaptureStatus::ParentSystem, "system parent status"))
        return false;
    return Expect(snapshot.parentProcessName == "System", "system parent name is stable sentinel");
}

bool TestRetrySnapshotAndBackoff()
{
    FakeProcessContextPlatform fake;
    fake.parentPidResult = ParentPidQueryResult::QueryFailed;
    fake.parentPidError = 0xC0000001;

    ProcessContextProvider provider(fake);
    const auto& first = provider.GetSnapshot();
    if (!Expect(first.valid, "ppid failure still returns current process snapshot"))
        return false;
    if (!Expect(first.status == ProcessCaptureStatus::PpidQueryFailed, "first failure preserves root cause"))
        return false;
    if (!Expect(first.retryState == ProcessRetryState::Pending, "first failure enters retry pending"))
        return false;
    if (!Expect(fake.queryParentPidCalls == 1, "first failure attempts ppid query"))
        return false;

    const auto& second = provider.GetSnapshot();
    if (!Expect(second.status == ProcessCaptureStatus::PpidQueryFailed, "before backoff preserves root cause"))
        return false;
    if (!Expect(second.retryState == ProcessRetryState::Pending, "before backoff returns retry snapshot"))
        return false;
    if (!Expect(fake.queryParentPidCalls == 1, "before backoff does not retry"))
        return false;

    fake.tick += 1000;
    provider.GetSnapshot();
    if (!Expect(fake.queryParentPidCalls == 2, "after first backoff retries"))
        return false;

    fake.tick += 5000;
    provider.GetSnapshot();
    if (!Expect(fake.queryParentPidCalls == 3, "after second backoff retries"))
        return false;

    fake.tick += 30000;
    const auto& exhausted = provider.GetSnapshot();
    if (!Expect(fake.queryParentPidCalls == 3, "retry exhausted does not attempt fourth capture"))
        return false;
    if (!Expect(exhausted.status == ProcessCaptureStatus::PpidQueryFailed, "retry exhausted preserves root cause"))
        return false;
    return Expect(exhausted.retryState == ProcessRetryState::Exhausted, "retry exhausted state");
}

bool TestFailureThenSuccessClearsRetry()
{
    FakeProcessContextPlatform fake;
    fake.parentPidResult = ParentPidQueryResult::QueryFailed;
    fake.parentPidError = 0xC0000001;

    ProcessContextProvider provider(fake);
    provider.GetSnapshot();
    fake.tick += 1000;
    fake.parentPidResult = ParentPidQueryResult::Success;

    const auto& success = provider.GetSnapshot();
    if (!Expect(success.status == ProcessCaptureStatus::Success, "retry can recover to success"))
        return false;
    if (!Expect(success.parentResolved, "recovered snapshot resolves parent"))
        return false;

    fake.parentPid = 300;
    fake.parentPath = L"C:\\Windows\\System32\\mshta.exe";
    fake.tick += 30000;
    const auto& stable = provider.GetSnapshot();
    if (!Expect(stable.parentPid == 100, "successful retry result is frozen"))
        return false;
    return Expect(fake.queryParentPidCalls == 2, "success clears retry path");
}

bool TestNtdllUnavailableIsObservable()
{
    FakeProcessContextPlatform fake;
    fake.parentPidResult = ParentPidQueryResult::NtdllUnavailable;

    ProcessContextProvider provider(fake);
    const auto& snapshot = provider.GetSnapshot();
    if (!Expect(snapshot.status == ProcessCaptureStatus::NtdllUnavailable,
                "ntdll unavailable is observable"))
        return false;
    return Expect(snapshot.retryState == ProcessRetryState::Pending,
                  "ntdll unavailable can be retried");
}

bool TestNtQuerySymbolUnavailableIsObservable()
{
    FakeProcessContextPlatform fake;
    fake.parentPidResult = ParentPidQueryResult::SymbolUnavailable;

    ProcessContextProvider provider(fake);
    const auto& snapshot = provider.GetSnapshot();
    if (!Expect(snapshot.status == ProcessCaptureStatus::NtQuerySymbolUnavailable,
                "ntquery symbol unavailable is observable"))
        return false;
    return Expect(ProcessCaptureStatusToString(snapshot.status) ==
                      std::string("ntquery-symbol-unavailable"),
                  "ntquery symbol unavailable has stable string form");
}

bool TestRetryStateStringMapping()
{
    if (!Expect(ProcessRetryStateToString(ProcessRetryState::None) == std::string("none"),
                "none retry state string"))
        return false;
    if (!Expect(ProcessRetryStateToString(ProcessRetryState::Pending) == std::string("pending"),
                "pending retry state string"))
        return false;
    return Expect(ProcessRetryStateToString(ProcessRetryState::Exhausted) == std::string("exhausted"),
                  "exhausted retry state string");
}

bool TestParentPathQueryFailedIsDistinct()
{
    FakeProcessContextPlatform fake;
    fake.parentPathResult = ProcessPathQueryResult::PathQueryFailed;
    fake.parentPathError = 1234;

    ProcessContextProvider provider(fake);
    const auto& snapshot = provider.GetSnapshot();
    if (!Expect(snapshot.status == ProcessCaptureStatus::ParentPathQueryFailed,
                "path query failure is distinct from internal error"))
        return false;
    return Expect(snapshot.errorDomain == ProcessErrorDomain::Win32 &&
                      snapshot.nativeError == 1234,
                  "path query failure records win32 error domain");
}

bool TestRetryExhaustedIsFastTerminalSnapshot()
{
    FakeProcessContextPlatform fake;
    fake.parentPidResult = ParentPidQueryResult::QueryFailed;
    fake.parentPidError = 0xC0000001;

    ProcessContextProvider provider(fake);
    provider.GetSnapshot();
    fake.tick += 1000;
    provider.GetSnapshot();
    fake.tick += 5000;
    provider.GetSnapshot();
    fake.tick += 30000;
    const auto& exhausted = provider.GetSnapshot();
    const int callsAtExhaustion = fake.queryParentPidCalls;

    fake.tick += 30000;
    const auto& stillExhausted = provider.GetSnapshot();
    if (!Expect(&exhausted == &stillExhausted,
                "retry exhausted snapshot is reused as terminal failure"))
        return false;
    return Expect(fake.queryParentPidCalls == callsAtExhaustion,
                  "retry exhausted fast path does not attempt recapture");
}

bool TestSnapshotStorageIsBounded()
{
    FakeProcessContextPlatform fake;
    fake.parentPidResult = ParentPidQueryResult::QueryFailed;
    fake.parentPidError = 0xC0000001;

    ProcessContextProvider provider(fake);
    provider.GetSnapshot();
    fake.tick += 1000;
    provider.GetSnapshot();
    fake.tick += 5000;
    provider.GetSnapshot();
    fake.tick += 30000;
    const auto& exhausted = provider.GetSnapshot();

    if (!Expect(exhausted.retryState == ProcessRetryState::Exhausted,
                "test reaches exhausted retry state"))
        return false;
    return Expect(provider.SnapshotCountForTesting() <= 4,
                  "snapshot storage is bounded");
}

bool TestConcurrentGetSnapshot()
{
    FakeProcessContextPlatform fake;
    ProcessContextProvider provider(fake);

    std::vector<std::thread> threads;
    std::vector<const ProcessContextSnapshot*> snapshots(16, nullptr);
    for (size_t i = 0; i < snapshots.size(); ++i) {
        threads.emplace_back([&provider, &snapshots, i]() {
            snapshots[i] = &provider.GetSnapshot();
        });
    }
    for (auto& thread : threads)
        thread.join();

    for (const auto* snapshot : snapshots) {
        if (!Expect(snapshot != nullptr, "concurrent snapshot pointer is non-null"))
            return false;
        if (!Expect(snapshot->valid || snapshot->status == ProcessCaptureStatus::Initializing,
                    "concurrent snapshot is valid or explicitly initializing"))
            return false;
    }
    return Expect(fake.queryParentPidCalls == 1, "concurrent success captures once");
}

bool TestConcurrentInitialCaptureReturnsInitializing()
{
    FakeProcessContextPlatform fake;
    fake.delayParentPid = true;
    ProcessContextProvider provider(fake);

    const ProcessContextSnapshot* first = nullptr;
    std::thread captureThread([&]() {
        first = &provider.GetSnapshot();
    });

    for (int i = 0; i < 100 && !fake.enteredParentPid.load(std::memory_order_acquire); ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(1));

    const auto& duringCapture = provider.GetSnapshot();
    captureThread.join();

    if (!Expect(first != nullptr, "first capture thread returned a snapshot"))
        return false;
    if (!Expect(duringCapture.status == ProcessCaptureStatus::Initializing,
                "lock contention during first capture returns initializing snapshot"))
        return false;
    return Expect(!duringCapture.valid, "initializing snapshot is not falsely valid");
}

} // namespace

int main()
{
    int failures = 0;
    failures += TestSuccessSnapshotIsImmutable() ? 0 : 1;
    failures += TestParentOpenDeniedKeepsValidSnapshot() ? 0 : 1;
    failures += TestParentProcessExitedStatus() ? 0 : 1;
    failures += TestParentSystemStatus() ? 0 : 1;
    failures += TestRetrySnapshotAndBackoff() ? 0 : 1;
    failures += TestFailureThenSuccessClearsRetry() ? 0 : 1;
    failures += TestNtdllUnavailableIsObservable() ? 0 : 1;
    failures += TestNtQuerySymbolUnavailableIsObservable() ? 0 : 1;
    failures += TestRetryStateStringMapping() ? 0 : 1;
    failures += TestParentPathQueryFailedIsDistinct() ? 0 : 1;
    failures += TestRetryExhaustedIsFastTerminalSnapshot() ? 0 : 1;
    failures += TestSnapshotStorageIsBounded() ? 0 : 1;
    failures += TestConcurrentGetSnapshot() ? 0 : 1;
    failures += TestConcurrentInitialCaptureReturnsInitializing() ? 0 : 1;

    if (failures != 0) {
        std::cerr << failures << " process context provider test(s) failed\n";
        return 1;
    }
    return 0;
}
