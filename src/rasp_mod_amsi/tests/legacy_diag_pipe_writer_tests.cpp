#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include "../../rasp_rule_engine/src/legacy_diag_pipe_writer.cpp"

#include <iostream>
#include <string>

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
    {
        LegacyDiagPipeWriter writer;
        LegacyDiagForwardStatus status = writer.Send("");
        if (!Expect(status == LegacyDiagForwardStatus::EmptyPayload, "empty payload is rejected before pipe open"))
            return 1;
    }

    {
        if (!Expect(MapCreateFileErrorForDiagPipe(ERROR_ACCESS_DENIED) == LegacyDiagForwardStatus::AccessDenied,
                    "access denied maps to AccessDenied"))
            return 1;
        if (!Expect(MapCreateFileErrorForDiagPipe(ERROR_FILE_NOT_FOUND) == LegacyDiagForwardStatus::PipeUnavailable,
                    "missing pipe maps to PipeUnavailable"))
            return 1;
        if (!Expect(MapCreateFileErrorForDiagPipe(ERROR_PIPE_BUSY) == LegacyDiagForwardStatus::PipeUnavailable,
                    "busy pipe maps to PipeUnavailable"))
            return 1;
        if (!Expect(MapCreateFileErrorForDiagPipe(ERROR_BROKEN_PIPE) == LegacyDiagForwardStatus::PipeUnavailable,
                    "generic create failure maps to PipeUnavailable"))
            return 1;
    }

    {
        if (!Expect(MapWriteResultForDiagPipe(TRUE, 8, 8) == LegacyDiagForwardStatus::Sent,
                    "complete write maps to Sent"))
            return 1;
        if (!Expect(MapWriteResultForDiagPipe(FALSE, 0, 8) == LegacyDiagForwardStatus::WriteFailed,
                    "failed write maps to WriteFailed"))
            return 1;
        if (!Expect(MapWriteResultForDiagPipe(TRUE, 4, 8) == LegacyDiagForwardStatus::WriteFailed,
                    "partial write maps to WriteFailed"))
            return 1;
    }

    {
        LegacyDiagPipeWriter writer;
        LegacyDiagForwardStatus status = writer.Send("{\"cat\":\"diag\"}");
        if (!Expect(status != LegacyDiagForwardStatus::Sent,
                    "missing real pipe does not report Sent in unit environment"))
            return 1;
    }

    return 0;
}

