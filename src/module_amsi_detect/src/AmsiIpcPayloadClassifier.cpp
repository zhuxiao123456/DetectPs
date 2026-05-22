//
// Created by Codex on 2026/5/22.
//

#include "AmsiIpcPayloadClassifier.h"

namespace Engine {
    namespace {

        bool ExtractTopLevelStringField(const std::string &payload,
                                        const char *fieldName,
                                        std::string &value)
        {
            const std::string key = std::string("\"") + fieldName + "\"";
            const std::string::size_type keyPos = payload.find(key);
            if (keyPos == std::string::npos) {
                return false;
            }

            const std::string::size_type colonPos = payload.find(':', keyPos + key.size());
            if (colonPos == std::string::npos) {
                return false;
            }

            std::string::size_type quotePos = payload.find('"', colonPos + 1);
            if (quotePos == std::string::npos) {
                return false;
            }

            ++quotePos;
            std::string result;
            bool escaping = false;
            for (std::string::size_type i = quotePos; i < payload.size(); ++i) {
                const char ch = payload[i];
                if (escaping) {
                    result.push_back(ch);
                    escaping = false;
                    continue;
                }
                if (ch == '\\') {
                    escaping = true;
                    continue;
                }
                if (ch == '"') {
                    value = result;
                    return true;
                }
                result.push_back(ch);
            }

            return false;
        }

    } // namespace

    AmsiIpcPayloadKind ClassifyAmsiEventPayload(const std::string &payload)
    {
        std::string cat;
        std::string sensor;
        const bool hasCat = ExtractTopLevelStringField(payload, "cat", cat);
        ExtractTopLevelStringField(payload, "sensor", sensor);

        if (hasCat && cat == "Detection") {
            return AmsiIpcPayloadKind::Detection;
        }
        if (hasCat && cat == "drain-ack") {
            return AmsiIpcPayloadKind::DrainAck;
        }
        if (hasCat && cat == "diag") {
            return AmsiIpcPayloadKind::DllDiagnosticLog;
        }
        if ((!hasCat || cat.empty()) && sensor == "RaspLog") {
            return AmsiIpcPayloadKind::DllDiagnosticLog;
        }

        return AmsiIpcPayloadKind::UnknownEvent;
    }

} // namespace Engine
