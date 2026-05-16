#include "demo_file_rule_provider.h"

#include "nlohmann/json.hpp"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << "FAIL: " << message << "\n";
        return false;
    }
    return true;
}

std::filesystem::path MakeTempDir()
{
    auto dir = std::filesystem::temp_directory_path() /
               ("demo_file_rule_provider_tests_" + std::to_string(GetCurrentProcessId()));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

void WriteText(const std::filesystem::path& path, const std::string& text)
{
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << text;
}

bool Build(DemoFileRuleProvider& provider,
           const std::string& command,
           amsi_ipc::AmsiRuleResponse& response)
{
    std::string error;
    return provider.BuildRulesResponse(command, response, error);
}

} // namespace

int main()
{
    bool ok = true;
    const auto tempDir = MakeTempDir();
    const auto rulesPath = tempDir / "rasp_rules.json";

    WriteText(rulesPath,
              R"({"version":1,"rules":[{"id":"AMSI-1","sensor":"AmsiProvider"},{"id":"OTHER-1","sensor":"OtherSensor"}]})");

    DemoFileRuleProvider provider(rulesPath.string());

    amsi_ipc::AmsiRuleResponse allRules;
    ok &= Expect(Build(provider, "GET_ALL_RULES", allRules), "GET_ALL_RULES succeeds");
    const auto allJson = nlohmann::json::parse(allRules.json);
    ok &= Expect(allJson.contains("rules"), "GET_ALL_RULES returns assembled root object");
    ok &= Expect(allJson["rules"].size() == 2, "GET_ALL_RULES keeps all rules");

    amsi_ipc::AmsiRuleResponse amsiRules;
    ok &= Expect(Build(provider, "GET_RULES", amsiRules), "GET_RULES succeeds");
    const auto amsiJson = nlohmann::json::parse(amsiRules.json);
    ok &= Expect(amsiJson.is_array(), "GET_RULES returns filtered array");
    ok &= Expect(amsiJson.size() == 1, "GET_RULES filters to AMSI rules");
    ok &= Expect(amsiJson[0]["id"].get<std::string>() == "AMSI-1", "GET_RULES preserves AMSI rule");

    amsi_ipc::AmsiRuleResponse unknown;
    std::string error;
    ok &= Expect(!provider.BuildRulesResponse("UNKNOWN", unknown, error), "unknown command fails");
    ok &= Expect(error.find("unknown command") != std::string::npos, "unknown command reports error");

    WriteText(rulesPath,
              R"({"version":1,"rules":[{"id":"AMSI-2","sensor":"AmsiProvider"}]})");
    amsi_ipc::AmsiRuleResponse cachedRules;
    ok &= Expect(Build(provider, "GET_RULES", cachedRules), "cached GET_RULES succeeds");
    ok &= Expect(nlohmann::json::parse(cachedRules.json)[0]["id"].get<std::string>() == "AMSI-1",
                 "provider keeps cached rules until invalidated");

    provider.InvalidateRuleCache();
    amsi_ipc::AmsiRuleResponse reloadedRules;
    ok &= Expect(Build(provider, "GET_RULES", reloadedRules), "GET_RULES succeeds after invalidate");
    ok &= Expect(nlohmann::json::parse(reloadedRules.json)[0]["id"].get<std::string>() == "AMSI-2",
                 "provider rebuilds rules after invalidate");

    std::filesystem::remove_all(tempDir);

    if (!ok) {
        return 1;
    }

    std::cout << "demo_file_rule_provider_tests passed\n";
    return 0;
}
