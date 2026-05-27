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
         * 从 JSON 字符串的最顶层（Top-Level）挖出指定 Key 对应的 String 类型 Value
         * @param payload  本地探针的原始json格式字符串
         * @param fieldName  需要寻找的键名
         * @param value  传出参数（引用传递）。若查找成功，该变量将被赋值为挖出来的字符串内容
         * @return 返回value
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
     * 它是整个数据收集链路的红绿灯。它通过调用工具函数拿到 cat (Category) 和 sensor 两个核心字段的值，随后应用安全引擎的分类矩阵规则
     * @param payload  待识别的原始 JSON 载荷字符串
     * @return  返回一个 AmsiIpcPayloadKind 强类型枚举值
     */
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
