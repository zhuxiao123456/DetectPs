#pragma once

#include <string>

namespace amsi_ipc {

struct AmsiControlStatusLine {
    std::string payload;
};

class IAmsiControlStatusSink {
public:
    virtual ~IAmsiControlStatusSink() = default;
    virtual void OnControlStatusLine(const AmsiControlStatusLine& status) = 0;
};

} // namespace amsi_ipc
