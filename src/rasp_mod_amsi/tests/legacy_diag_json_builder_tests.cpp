#include "legacy_diag_json_builder.h"

#include <iostream>
#include <string>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition)
        std::cerr << "FAIL: " << message << "\n";
    return condition;
}

LegacyDiagJsonBuildInput BaseInput()
{
    LegacyDiagJsonBuildInput input;
    input.id = "fixed-id";
    input.timestamp = "2026-01-02T03:04:05.006Z";
    input.module = "fixed-module";
    input.pattern = "fixed-pattern";
    input.message = "hello world";
    return input;
}

} // namespace

int main()
{
    {
        LegacyDiagJsonBuilder builder;
        LegacyDiagJsonBuildResult result = builder.Build(BaseInput());

        const std::string expected =
            "{\"id\":\"fixed-id\",\"ts\":\"2026-01-02T03:04:05.006Z\","
            "\"sev\":\"info\",\"act\":\"audit\",\"cat\":\"diag\","
            "\"mod\":\"fixed-module\",\"sensor\":\"RaspLog\","
            "\"rule\":\"\",\"desc\":\"hello world\","
            "\"method\":\"\",\"url\":\"\",\"ip\":\"\",\"ua\":\"\","
            "\"pattern\":\"fixed-pattern\",\"payload\":\"\"}";

        if (!Expect(result.compactJson == expected, "raw JSON preserves legacy diag field order"))
            return 1;
        if (!Expect(result.compactJson.empty() || result.compactJson.back() != '\n',
                    "legacy diag JSON does not append newline"))
            return 1;
        if (!Expect(!result.truncated, "short diag JSON is not truncated"))
            return 1;
        if (!Expect(result.compactJson.size() <= 2047, "short diag JSON respects legacy effective line size"))
            return 1;
    }

    {
        LegacyDiagJsonBuilder builder;
        LegacyDiagJsonBuildInput input = BaseInput();
        input.message = "quote \" slash \\ newline\n carriage\r tab\t";
        LegacyDiagJsonBuildResult result = builder.Build(input);

        if (!Expect(result.compactJson.find("quote \\\" slash \\\\ newline\\n carriage\\r tab\\t") != std::string::npos,
                    "special characters preserve legacy escaping"))
            return 1;
    }

    {
        LegacyDiagJsonBuilder builder;
        LegacyDiagJsonBuildInput input = BaseInput();
        input.message = std::string("control-") + static_cast<char>(0x01) + static_cast<char>(0x1f);
        LegacyDiagJsonBuildResult result = builder.Build(input);

        if (!Expect(result.compactJson.find("\\u0001") != std::string::npos,
                    "control character 0x01 uses lowercase hex escape"))
            return 1;
        if (!Expect(result.compactJson.find("\\u001f") != std::string::npos,
                    "control character 0x1f uses lowercase hex escape"))
            return 1;
        if (!Expect(result.compactJson.find("\\u001F") == std::string::npos,
                    "control character escape does not use uppercase hex"))
            return 1;
    }

    {
        LegacyDiagJsonBuilder builder;
        LegacyDiagJsonBuildInput input = BaseInput();
        input.message = "中文日志";
        LegacyDiagJsonBuildResult result = builder.Build(input);

        if (!Expect(result.compactJson.find("中文日志") != std::string::npos,
                    "UTF-8 diagnostic text is preserved as legacy bytes"))
            return 1;
    }

    {
        LegacyDiagJsonBuilder builder;
        LegacyDiagJsonBuildInput input = BaseInput();
        input.message.clear();
        LegacyDiagJsonBuildResult result = builder.Build(input);

        if (!Expect(result.compactJson.find("\"desc\":\"\"") != std::string::npos,
                    "empty message produces empty desc"))
            return 1;
        if (!Expect(!result.truncated, "empty message is not truncated"))
            return 1;
    }

    {
        LegacyDiagJsonBuilder builder;
        LegacyDiagJsonBuildInput input = BaseInput();
        input.message.assign(4096, 'A');
        LegacyDiagJsonBuildResult result = builder.Build(input);

        if (!Expect(result.truncated, "oversized diag JSON is marked truncated"))
            return 1;
        if (!Expect(result.compactJson.size() == 2047, "oversized diag JSON fills the legacy effective line size"))
            return 1;
        if (!Expect(result.compactJson.find('\0') == std::string::npos,
                    "compact JSON does not include the snprintf NUL terminator"))
            return 1;
    }

    return 0;
}
