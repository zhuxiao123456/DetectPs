#include "legacy_diag_json_builder.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <string_view>

namespace {

std::string EscapeLegacyDiagJson(std::string_view text)
{
    std::string escaped;
    escaped.reserve(text.size());

    for (unsigned char ch : text) {
        switch (ch) {
        case '"':
            escaped += "\\\"";
            break;
        case '\\':
            escaped += "\\\\";
            break;
        case '\n':
            escaped += "\\n";
            break;
        case '\r':
            escaped += "\\r";
            break;
        case '\t':
            escaped += "\\t";
            break;
        default:
            if (ch < 0x20) {
                char esc[8];
                std::snprintf(esc, sizeof(esc), "\\u%04x", ch);
                escaped += esc;
            } else {
                escaped.push_back(static_cast<char>(ch));
            }
            break;
        }
    }

    return escaped;
}

} // namespace

const char* SeverityToString(RaspDiagSeverity severity)
{
    switch (severity) {
    case RaspDiagSeverity::Debug:
        return "debug";
    case RaspDiagSeverity::Warning:
        return "warning";
    case RaspDiagSeverity::Error:
        return "error";
    case RaspDiagSeverity::Info:
    default:
        return "info";
    }
}

LegacyDiagJsonBuildResult LegacyDiagJsonBuilder::Build(const LegacyDiagJsonBuildInput& input) const
{
    const std::string desc = EscapeLegacyDiagJson(input.message);
    const std::string dllInstanceId = EscapeLegacyDiagJson(input.dllInstanceId);
    const std::string processName = EscapeLegacyDiagJson(input.processName);
    const std::string processPath = EscapeLegacyDiagJson(input.processPath);
    const std::string parentProcessName = EscapeLegacyDiagJson(input.parentProcessName);
    const std::string parentProcessPath = EscapeLegacyDiagJson(input.parentProcessPath);
    const char* severity = SeverityToString(input.severity);

    char line[4096] = {};
    const int written = std::snprintf(
        line,
        sizeof(line),
        "{\"sev\":\"%s\",\"cat\":\"diag\","
        "\"desc\":\"%s\","
        "\"dllInstanceId\":\"%s\","
        "\"pid\":%lu,"
        "\"processName\":\"%s\","
        "\"processPath\":\"%s\","
        "\"parentPid\":%lu,"
        "\"parentProcessName\":\"%s\","
        "\"parentProcessPath\":\"%s\"}",
        severity,
        desc.c_str(),
        dllInstanceId.c_str(),
        static_cast<unsigned long>(input.pid),
        processName.c_str(),
        processPath.c_str(),
        static_cast<unsigned long>(input.parentPid),
        parentProcessName.c_str(),
        parentProcessPath.c_str());

    LegacyDiagJsonBuildResult result;
    result.truncated = (written < 0) || (written >= static_cast<int>(sizeof(line)));
    result.compactJson.assign(line, std::strlen(line));
    return result;
}