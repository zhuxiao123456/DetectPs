//
// Created by Codex on 2026/5/22.
//

#ifndef CSA_ENGINE_AMSI_IPC_PAYLOAD_CLASSIFIER_H
#define CSA_ENGINE_AMSI_IPC_PAYLOAD_CLASSIFIER_H

#include <string>

namespace Engine {

    enum class AmsiIpcPayloadKind {
        Detection,
        DllDiagnosticLog,
        DrainAck,
        UnknownEvent,
        Status
    };

    AmsiIpcPayloadKind ClassifyAmsiEventPayload(const std::string &payload);

} // namespace Engine

#endif //CSA_ENGINE_AMSI_IPC_PAYLOAD_CLASSIFIER_H
