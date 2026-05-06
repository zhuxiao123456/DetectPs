#include "legacy_pipe_event_transport.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <iostream>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition)
        std::cerr << "FAIL: " << message << "\n";
    return condition;
}

} // namespace

int main()
{
    if (!Expect(MapCreateFileErrorForEventPipe(ERROR_FILE_NOT_FOUND) == EventTransportStatus::Unavailable,
                "missing pipe maps to unavailable"))
        return 1;
    if (!Expect(MapCreateFileErrorForEventPipe(ERROR_PIPE_BUSY) == EventTransportStatus::Unavailable,
                "busy pipe maps to unavailable"))
        return 1;
    if (!Expect(MapCreateFileErrorForEventPipe(ERROR_ACCESS_DENIED) == EventTransportStatus::AccessDenied,
                "create access denied maps to access denied"))
        return 1;
    if (!Expect(MapCreateFileErrorForEventPipe(ERROR_INVALID_PARAMETER) == EventTransportStatus::Failed,
                "other create error maps to failed"))
        return 1;

    if (!Expect(MapWriteFileErrorForEventPipe(ERROR_ACCESS_DENIED) == EventTransportStatus::AccessDenied,
                "write access denied maps to access denied"))
        return 1;
    if (!Expect(MapWriteFileErrorForEventPipe(ERROR_BROKEN_PIPE) == EventTransportStatus::Failed,
                "write failure maps to failed"))
        return 1;

    if (!Expect(MapWriteResultForEventPipe(true, 5, 5) == EventTransportStatus::Sent,
                "complete write maps to sent"))
        return 1;
    if (!Expect(MapWriteResultForEventPipe(true, 4, 5) == EventTransportStatus::Failed,
                "partial write maps to failed"))
        return 1;
    if (!Expect(MapWriteResultForEventPipe(false, 0, 5) == EventTransportStatus::Failed,
                "generic failed write maps to failed"))
        return 1;

    {
        LegacyPipeEventTransport transport(LR"(\\.\pipe\definitely_not_exists_for_test)");
        EventTransportStatus status = transport.Send("{}", 0);
        if (!Expect(status != EventTransportStatus::Sent,
                    "non-existing pipe send does not report sent"))
            return 1;
    }

    return 0;
}
