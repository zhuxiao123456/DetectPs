#pragma once

#include <string>

namespace amsi_ipc {

struct AmsiEventLine {
    std::string payload;
};

class IAmsiEventSink {
public:
    virtual ~IAmsiEventSink() = default;
    virtual void OnEventLine(const AmsiEventLine& event) = 0;
};

} // namespace amsi_ipc
