#pragma once

#include <cstddef>
#include <string_view>

// Minimal diagnostic logger runtime seam.
//
// Runtime implementations may coordinate synchronization and wake signaling
// behind this interface. This header must remain free of platform handles,
// transports, formatting schemas, and detection decision semantics.
class IDiagLoggerRuntime {
public:
    virtual ~IDiagLoggerRuntime() = default;
    virtual bool TryEnqueue(std::string_view text) = 0;
    virtual size_t PendingCount() const = 0;
};
