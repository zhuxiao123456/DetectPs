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

LegacyDiagJsonBuildResult LegacyDiagJsonBuilder::Build(const LegacyDiagJsonBuildInput& input) const
{
    const std::string desc = EscapeLegacyDiagJson(input.message);

    char line[2048] = {};
    const int written = std::snprintf(
        line,
        sizeof(line),
        "{\"id\":\"%s\",\"ts\":\"%s\","
        "\"sev\":\"info\",\"act\":\"audit\",\"cat\":\"diag\","
        "\"mod\":\"%s\",\"sensor\":\"RaspLog\","
        "\"rule\":\"\",\"desc\":\"%s\","
        "\"method\":\"\",\"url\":\"\",\"ip\":\"\",\"ua\":\"\","
        "\"pattern\":\"%s\",\"payload\":\"\"}",
        input.id.c_str(),
        input.timestamp.c_str(),
        input.module.c_str(),
        desc.c_str(),
        input.pattern.c_str());

    LegacyDiagJsonBuildResult result;
    result.truncated = (written < 0) || (written >= static_cast<int>(sizeof(line)));
    result.compactJson.assign(line, std::strlen(line));
    return result;
}
