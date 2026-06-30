#include <windows.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

// Keep this spike reader aligned with ReadOnePipeChunk/ReadMessagePipeWithLimit
// in src/rasp_rule_engine/src/rasp_sentry_base.cpp.
constexpr DWORD kReadChunkBytes = 64 * 1024;
constexpr DWORD kPerReadTimeoutMs = 5000;
constexpr DWORD kTotalReadTimeoutMs = 10000;
constexpr size_t kTwoMb = 2 * 1024 * 1024;

struct ReadOneChunkResult {
    bool complete = false;
    DWORD error = ERROR_SUCCESS;
    DWORD bytesThisRead = 0;
};

struct ReadMessageStats {
    DWORD chunks = 0;
    DWORD lastError = ERROR_SUCCESS;
    size_t totalBytesRead = 0;
    bool totalTimeout = false;
    bool perReadTimeout = false;
    bool sawMoreData = false;
};

bool Expect(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << "FAIL: " << message << "\n";
        return false;
    }
    return true;
}

std::wstring UniquePipeName(const wchar_t* suffix)
{
    return std::wstring(LR"(\\.\pipe\amsi_rule_large_message_spike_)") +
           std::to_wstring(GetCurrentProcessId()) +
           L"_" +
           suffix;
}

std::string MakePayload(size_t bytes)
{
    std::string payload;
    payload.resize(bytes);
    for (size_t i = 0; i < bytes; ++i) {
        payload[i] = static_cast<char>('A' + (i % 23));
    }
    return payload;
}

ReadOneChunkResult ReadOnePipeChunk(HANDLE pipe,
                                    char* buffer,
                                    DWORD bufferBytes,
                                    DWORD timeoutMs)
{
    ReadOneChunkResult result;
    if (pipe == INVALID_HANDLE_VALUE || buffer == nullptr || bufferBytes == 0) {
        result.error = ERROR_INVALID_PARAMETER;
        return result;
    }

    OVERLAPPED ov = {};
    ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!ov.hEvent) {
        result.error = GetLastError();
        return result;
    }

    DWORD bytesThisRead = 0;
    const BOOL readOk = ReadFile(pipe, buffer, bufferBytes, &bytesThisRead, &ov);
    if (readOk) {
        CloseHandle(ov.hEvent);
        result.complete = true;
        result.error = ERROR_SUCCESS;
        result.bytesThisRead = bytesThisRead;
        return result;
    }

    const DWORD err = GetLastError();
    if (err == ERROR_MORE_DATA) {
        DWORD transferred = 0;
        if (bytesThisRead == 0) {
            GetOverlappedResult(pipe, &ov, &transferred, FALSE);
        }
        CloseHandle(ov.hEvent);
        result.complete = false;
        result.error = ERROR_MORE_DATA;
        result.bytesThisRead = bytesThisRead != 0 ? bytesThisRead : transferred;
        return result;
    }

    if (err == ERROR_IO_PENDING) {
        const DWORD waitRc = WaitForSingleObject(ov.hEvent, timeoutMs);
        if (waitRc == WAIT_OBJECT_0) {
            DWORD transferred = 0;
            const BOOL overlappedOk = GetOverlappedResult(pipe, &ov, &transferred, FALSE);
            if (overlappedOk) {
                CloseHandle(ov.hEvent);
                result.complete = true;
                result.error = ERROR_SUCCESS;
                result.bytesThisRead = transferred;
                return result;
            }

            const DWORD completionErr = GetLastError();
            CloseHandle(ov.hEvent);
            result.complete = false;
            result.error = completionErr;
            result.bytesThisRead = transferred;
            return result;
        }

        if (waitRc == WAIT_TIMEOUT) {
            CancelIo(pipe);
            DWORD ignored = 0;
            GetOverlappedResult(pipe, &ov, &ignored, TRUE);
            CloseHandle(ov.hEvent);
            result.complete = false;
            result.error = WAIT_TIMEOUT;
            result.bytesThisRead = 0;
            return result;
        }

        const DWORD waitErr = GetLastError();
        CancelIo(pipe);
        DWORD ignored = 0;
        GetOverlappedResult(pipe, &ov, &ignored, TRUE);
        CloseHandle(ov.hEvent);
        result.complete = false;
        result.error = waitErr;
        result.bytesThisRead = 0;
        return result;
    }

    CloseHandle(ov.hEvent);
    result.complete = false;
    result.error = err;
    result.bytesThisRead = bytesThisRead;
    return result;
}

bool ReadMessageWithLimit(HANDLE pipe,
                          std::string& response,
                          size_t maxBytes,
                          ReadMessageStats& stats)
{
    response.clear();
    stats = ReadMessageStats{};
    const ULONGLONG deadline = GetTickCount64() + kTotalReadTimeoutMs;
    std::vector<char> chunk(kReadChunkBytes);

    for (;;) {
        const ULONGLONG now = GetTickCount64();
        if (now >= deadline) {
            stats.totalTimeout = true;
            stats.lastError = WAIT_TIMEOUT;
            response.clear();
            return false;
        }

        const DWORD remainingTimeout =
            static_cast<DWORD>((std::min<ULONGLONG>)(kPerReadTimeoutMs, deadline - now));
        const ReadOneChunkResult one =
            ReadOnePipeChunk(pipe, chunk.data(), static_cast<DWORD>(chunk.size()), remainingTimeout);

        ++stats.chunks;
        stats.lastError = one.error;

        if (one.bytesThisRead > 0) {
            if (response.size() + one.bytesThisRead > maxBytes) {
                stats.totalBytesRead = response.size() + one.bytesThisRead;
                response.clear();
                return false;
            }
            response.append(chunk.data(), one.bytesThisRead);
            stats.totalBytesRead = response.size();
        }

        if (one.complete) {
            return !response.empty();
        }

        if (one.error == ERROR_MORE_DATA) {
            stats.sawMoreData = true;
            continue;
        }

        if (one.error == WAIT_TIMEOUT) {
            if (GetTickCount64() >= deadline) {
                stats.totalTimeout = true;
            } else {
                stats.perReadTimeout = true;
            }
        }

        response.clear();
        return false;
    }
}

bool ExchangeLargePayload(DWORD outBufferBytes,
                          size_t payloadBytes,
                          const wchar_t* suffix,
                          ReadMessageStats& stats)
{
    const std::wstring pipeName = UniquePipeName(suffix);
    const std::string payload = MakePayload(payloadBytes);
    std::atomic<bool> serverWriteOk{false};
    std::atomic<DWORD> serverWriteError{ERROR_SUCCESS};
    std::atomic<DWORD> serverWritten{0};

    HANDLE server = CreateNamedPipeW(pipeName.c_str(),
                                     PIPE_ACCESS_DUPLEX,
                                     PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                     1,
                                     outBufferBytes,
                                     256,
                                     0,
                                     nullptr);
    if (server == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateNamedPipeW failed GLE=" << GetLastError() << "\n";
        return false;
    }

    std::thread serverThread([&]() {
        const BOOL connected = ConnectNamedPipe(server, nullptr);
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED) {
            serverWriteError.store(GetLastError());
            CloseHandle(server);
            return;
        }

        char request[64] = {};
        DWORD requestBytes = 0;
        if (!ReadFile(server, request, static_cast<DWORD>(sizeof(request)), &requestBytes, nullptr)) {
            serverWriteError.store(GetLastError());
            DisconnectNamedPipe(server);
            CloseHandle(server);
            return;
        }

        DWORD written = 0;
        const BOOL writeOk =
            WriteFile(server, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr);
        serverWritten.store(written);
        if (!writeOk || written != payload.size()) {
            serverWriteError.store(GetLastError());
            DisconnectNamedPipe(server);
            CloseHandle(server);
            return;
        }

        FlushFileBuffers(server);
        serverWriteOk.store(true);
        DisconnectNamedPipe(server);
        CloseHandle(server);
    });

    HANDLE client = CreateFileW(pipeName.c_str(),
                                GENERIC_READ | GENERIC_WRITE,
                                0,
                                nullptr,
                                OPEN_EXISTING,
                                FILE_FLAG_OVERLAPPED,
                                nullptr);
    if (client == INVALID_HANDLE_VALUE) {
        serverThread.join();
        std::cerr << "CreateFileW failed GLE=" << GetLastError() << "\n";
        return false;
    }

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(client, &mode, nullptr, nullptr);

    const char request[] = "GET_ALL_RULES\n";
    DWORD written = 0;
    WriteFile(client, request, static_cast<DWORD>(sizeof(request) - 1), &written, nullptr);

    std::string response;
    const bool readOk = ReadMessageWithLimit(client, response, payloadBytes, stats);
    CloseHandle(client);
    serverThread.join();

    const bool contentOk = response == payload;
    if (!readOk || !contentOk || !serverWriteOk.load()) {
        size_t firstDiff = static_cast<size_t>(-1);
        const size_t compareBytes = (std::min)(response.size(), payload.size());
        for (size_t i = 0; i < compareBytes; ++i) {
            if (response[i] != payload[i]) {
                firstDiff = i;
                break;
            }
        }
        std::cerr << "large payload exchange failed outBuffer=" << outBufferBytes
                  << " payload=" << payloadBytes
                  << " responseSize=" << response.size()
                  << " readOk=" << readOk
                  << " contentOk=" << contentOk
                  << " firstDiff=" << firstDiff
                  << " responseByte="
                  << (firstDiff != static_cast<size_t>(-1) && firstDiff < response.size()
                          ? static_cast<int>(static_cast<unsigned char>(response[firstDiff]))
                          : -1)
                  << " payloadByte="
                  << (firstDiff != static_cast<size_t>(-1) && firstDiff < payload.size()
                          ? static_cast<int>(static_cast<unsigned char>(payload[firstDiff]))
                          : -1)
                  << " serverWriteOk=" << serverWriteOk.load()
                  << " serverWritten=" << serverWritten.load()
                  << " serverError=" << serverWriteError.load()
                  << " chunks=" << stats.chunks
                  << " sawMoreData=" << stats.sawMoreData
                  << " lastError=" << stats.lastError
                  << "\n";
        return false;
    }

    return true;
}

bool ClientWithoutRequestBlocksServerRead()
{
    const std::wstring pipeName = UniquePipeName(L"no_request");
    std::atomic<bool> readReturned{false};

    HANDLE server = CreateNamedPipeW(pipeName.c_str(),
                                     PIPE_ACCESS_DUPLEX,
                                     PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                     1,
                                     512 * 1024,
                                     256,
                                     0,
                                     nullptr);
    if (server == INVALID_HANDLE_VALUE) {
        return false;
    }

    std::thread serverThread([&]() {
        const BOOL connected = ConnectNamedPipe(server, nullptr);
        if (connected || GetLastError() == ERROR_PIPE_CONNECTED) {
            char request[64] = {};
            DWORD bytesRead = 0;
            ReadFile(server, request, static_cast<DWORD>(sizeof(request)), &bytesRead, nullptr);
            readReturned.store(true);
        }
        DisconnectNamedPipe(server);
        CloseHandle(server);
    });

    HANDLE client = CreateFileW(pipeName.c_str(),
                                GENERIC_READ | GENERIC_WRITE,
                                0,
                                nullptr,
                                OPEN_EXISTING,
                                0,
                                nullptr);
    if (client == INVALID_HANDLE_VALUE) {
        serverThread.join();
        return false;
    }

    Sleep(200);
    const bool stillBlocked = !readReturned.load();
    CloseHandle(client);
    serverThread.join();
    return stillBlocked && readReturned.load();
}

bool ClientWithoutReadingBlocksServerWrite()
{
    const std::wstring pipeName = UniquePipeName(L"no_read");
    const std::string payload = MakePayload(kTwoMb);
    std::atomic<bool> writeReturned{false};

    HANDLE server = CreateNamedPipeW(pipeName.c_str(),
                                     PIPE_ACCESS_DUPLEX,
                                     PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                                     1,
                                     512 * 1024,
                                     256,
                                     0,
                                     nullptr);
    if (server == INVALID_HANDLE_VALUE) {
        return false;
    }

    std::thread serverThread([&]() {
        const BOOL connected = ConnectNamedPipe(server, nullptr);
        if (connected || GetLastError() == ERROR_PIPE_CONNECTED) {
            char request[64] = {};
            DWORD bytesRead = 0;
            if (ReadFile(server, request, static_cast<DWORD>(sizeof(request)), &bytesRead, nullptr)) {
                DWORD written = 0;
                WriteFile(server,
                          payload.data(),
                          static_cast<DWORD>(payload.size()),
                          &written,
                          nullptr);
                writeReturned.store(true);
            }
        }
        DisconnectNamedPipe(server);
        CloseHandle(server);
    });

    HANDLE client = CreateFileW(pipeName.c_str(),
                                GENERIC_READ | GENERIC_WRITE,
                                0,
                                nullptr,
                                OPEN_EXISTING,
                                0,
                                nullptr);
    if (client == INVALID_HANDLE_VALUE) {
        serverThread.join();
        return false;
    }

    const char request[] = "GET_ALL_RULES\n";
    DWORD written = 0;
    WriteFile(client, request, static_cast<DWORD>(sizeof(request) - 1), &written, nullptr);

    Sleep(200);
    const bool stillBlocked = !writeReturned.load();
    CloseHandle(client);
    serverThread.join();
    return stillBlocked && writeReturned.load();
}

} // namespace

int main()
{
    bool ok = true;

    ReadMessageStats groupA;
    ok &= Expect(ExchangeLargePayload(512 * 1024, kTwoMb, L"group_a", groupA),
                 "512KB out buffer can write/read 2MB wire payload");
    ok &= Expect(groupA.chunks > 1 && groupA.sawMoreData,
                 "512KB out buffer 2MB payload uses multiple chunks and ERROR_MORE_DATA");

    ReadMessageStats groupB;
    ok &= Expect(ExchangeLargePayload(2 * 1024 * 1024, kTwoMb, L"group_b", groupB),
                 "2MB out buffer can write/read 2MB wire payload");
    ok &= Expect(groupB.chunks > 1 && groupB.sawMoreData,
                 "2MB out buffer 2MB payload uses multiple chunks and ERROR_MORE_DATA");

    ok &= Expect(ClientWithoutRequestBlocksServerRead(),
                 "client that connects without sending request blocks synchronous server ReadFile");
    ok &= Expect(ClientWithoutReadingBlocksServerWrite(),
                 "client that sends request without reading blocks synchronous server WriteFile");

    if (!ok) {
        return 1;
    }

    std::cout << "rule_pipe_large_message_spike_tests passed\n";
    std::cout << "groupA chunks=" << groupA.chunks
              << " bytes=" << groupA.totalBytesRead
              << " sawMoreData=" << groupA.sawMoreData << "\n";
    std::cout << "groupB chunks=" << groupB.chunks
              << " bytes=" << groupB.totalBytesRead
              << " sawMoreData=" << groupB.sawMoreData << "\n";
    return 0;
}
