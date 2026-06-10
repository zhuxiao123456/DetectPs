//
// Created by z00840245 on 2026/5/22.
//

#include "AmsiIpcPayloadClassifier.h"

namespace Engine {
    namespace {

        bool DecodeJsonString(const std::string &payload,
                              std::string::size_type quotePos,
                              std::string &value)
        {
            std::string result;
            bool escaping = false;
            for (std::string::size_type i = quotePos + 1; i < payload.size(); ++i) {
                const char ch = payload[i];
                if (escaping) {
                    switch (ch) {
                        case '"':
                        case '\\':
                        case '/':
                            result.push_back(ch);
                            break;
                        case 'b':
                            result.push_back('\b');
                            break;
                        case 'f':
                            result.push_back('\f');
                            break;
                        case 'n':
                            result.push_back('\n');
                            break;
                        case 'r':
                            result.push_back('\r');
                            break;
                        case 't':
                            result.push_back('\t');
                            break;
                        case 'u':
                            return false;
                        default:
                            return false;
                    }
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

        /**
         * ?? JSON ???????????Top-Level???????? Key ????? String ???? Value
         * @param payload  ??????????json????????
         * @param fieldName  ??????????
         * @param value  ???????????????????????????????????????????????????????????
         * @return ????value
         */
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

            std::string::size_type valuePos = colonPos + 1;
            while (valuePos < payload.size() &&
                   (payload[valuePos] == ' ' || payload[valuePos] == '\t' ||
                    payload[valuePos] == '\r' || payload[valuePos] == '\n')) {
                ++valuePos;
            }

            if (valuePos >= payload.size() || payload[valuePos] != '"') {
                return false;
            }

            return DecodeJsonString(payload, valuePos, value);
        }

    } // namespace

    /**
     * ?????????????????¡¤???????????????¨´????????? cat (Category) ??¦Å?????????e????????????????
     * @param payload  ???????? JSON ????????
     * @return  ??????? AmsiIpcPayloadKind ?????????
     */
    AmsiIpcPayloadKind ClassifyAmsiEventPayload(const std::string &payload)
    {
        std::string cat;
        const bool hasCat = ExtractTopLevelStringField(payload, "cat", cat);
        if (hasCat && cat == "Detection") {
            return AmsiIpcPayloadKind::Detection;
        }
        if (hasCat && cat == "drain-ack") {
            return AmsiIpcPayloadKind::DrainAck;
        }
        if (hasCat && cat == "diag") {
            return AmsiIpcPayloadKind::DllDiagnosticLog;
        }

        return AmsiIpcPayloadKind::UnknownEvent;
    }

} // namespace Engine
