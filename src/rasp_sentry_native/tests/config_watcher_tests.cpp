#include "config_watcher.h"

#include "amsi_rule_provider.h"

#include <iostream>
#include <string>

namespace {

class FakeRuleProvider final : public amsi_ipc::IAmsiRuleProvider {
public:
    bool BuildRulesResponse(const std::string&,
                            amsi_ipc::AmsiRuleResponse&,
                            std::string&) override
    {
        return false;
    }

    void InvalidateRuleCache() override
    {
        ++invalidateCalls;
    }

    int invalidateCalls = 0;
};

bool Expect(bool condition, const char* message)
{
    if (!condition) {
        std::cerr << "FAIL: " << message << "\n";
        return false;
    }
    return true;
}

} // namespace

int main()
{
    bool ok = true;
    FakeRuleProvider provider;
    ConfigWatcher watcher("C:\\RaspSentry\\rasp_rules.json", &provider);

    watcher.InvalidateRuleCacheForTest();

    ok &= Expect(provider.invalidateCalls == 1,
                 "ConfigWatcher invalidates injected rule provider");

    if (!ok) {
        return 1;
    }

    std::cout << "config_watcher_tests passed\n";
    return 0;
}
