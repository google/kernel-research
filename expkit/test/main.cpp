#include <memory>
#include <vector>
#include "test/TargetDbTests.cpp"

#define RED(s)    "\033[1;31m" s "\033[0;0m"
#define GREEN(s)  "\033[1;32m" s "\033[0;0m"
#define YELLOW(s) "\033[1;33m" s "\033[0;0m"

int main() {
    std::vector<std::unique_ptr<TestSuite>> testSuites;
    testSuites.push_back(std::make_unique<TargetDbTests>());

    std::vector<std::string> failedTests;

    for (auto& testSuite : testSuites) {
        printf("===== TEST SUITE ::: " YELLOW("%s") " (%s) ::: =====\n", testSuite->class_name.c_str(), testSuite->desc.c_str());
        for (auto& test : testSuite->tests) {
            printf("[+] Running test: " YELLOW("%s") " (%s) \n", test.func_name.c_str(), test.desc.c_str());
            testSuite->logs.clear();
            try {
                test.func();
                printf("[+] Test ran successfully.");
            } catch(std::exception& exc) {
                failedTests.push_back(format_str("%s::%s", testSuite->class_name.c_str(), test.func_name.c_str()));
                printf("[!] Test failed with: " RED("%s") "\n", exc.what());
                if (!testSuite->logs.empty()) {
                    printf("  Logs:\n");
                    for (auto& log : testSuite->logs)
                        printf("    %s\n", log.c_str());
                }
            }
        }
    }

    printf("\n===== SUMMARY =====\n");
    if (failedTests.empty())
        printf("[+] " GREEN("SUCCESS") ".\n");
    else
        printf("[!] " RED("FAIL") ".\n[!] The following tests failed: " RED("%s") "\n", str_concat(", ", failedTests).c_str());

    return failedTests.empty() ? 0 : 1;
}