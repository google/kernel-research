#include <memory>
#include <vector>
#include <string>
#include <iostream>
#include "test/TestRunner.h"
#include "test/logging/TapLogger.h"
#include "test/tests/TargetDbTests.h"
#include "test/tests/KpwnTests.h"
#include "test/tests/RopActionTests.h"
#include "test/tests/SymbolsTests.h"
#include "test/tests/PivotTests.h"
#include "util/ArgumentParser.h"

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
        runner_.Add(new RopActionTests());

        runner_.SetSuiteFilter(args_.getOption("test-suites"));
        runner_.SetTestFilter(args_.getOption("tests").value_or("^TODO"));
        runner_.SetTargetDbPath(args_.getOption("target-db").value_or("test/artifacts/targets.kpwn"));
        runner_.SetRepeatCount(args_.getInt("repeat").value_or(1));

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
