#include <memory>
#include <vector>
#include <string>
#include <iostream>
#include "test/TestRunner.cpp"
#include "test/logging/TapLogger.cpp"
#include "test/tests/TargetDbTests.cpp"
#include "test/tests/KpwnTests.cpp"
#include "test/tests/SymbolsTests.cpp"
#include "test/tests/PivotTests.cpp"
#include "util/ArgumentParser.cpp"

class Main {
    ArgumentParser args_;
    TestRunner runner_;

    void ListTests() {
        for (auto& testSuite : runner_.GetTestSuites()) {
            cout << testSuite->class_name << ": ";
            for (int i = 0; i < testSuite->tests.size(); i++)
                cout << (i == 0 ? "" : ", ") << testSuite->tests[i].func_name;
            cout << "\n";
        }
    }
public:
    Main(int argc, const char* argv[]): args_(argc, argv) {
        runner_.Add(new TargetDbTests());
        runner_.Add(new KpwnTests());
        runner_.Add(new SymbolsTest());
        runner_.Add(new PivotTests());
        runner_.Add(new PivotKpwnTests());

        runner_.SetSuiteFilter(args_.getOption("test-suites"));
        runner_.SetTestFilter(args_.getOption("tests"));
        runner_.SetTargetDbPath(args_.getOption("target-db").value_or("test/artifacts/targets.kpwn"));

        if (args_.getOption("tap"))
            runner_.SetLogger(new TapLogger());
    }

    int Run() {
        auto& posArgs = args_.getPositionalArgs();
        if (posArgs.size() >= 1 && posArgs[0] == "list") {
            ListTests();
        } else if (posArgs.size() == 0 || posArgs[0] == "run") {
            return runner_.Run(args_.getInt("skip").value_or(0)) ? 0 : 1;
        } else {
            cerr << "Unknown command." << endl;
            return 1;
        }

        return 0;
    }
};

int main(int argc, const char* argv[]) {
    return Main(argc, argv).Run();
}
