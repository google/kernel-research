#include <memory>
#include <vector>
#include <string>
#include <iostream>
#include "test/TestRunner.cpp"
#include "test/tests/TargetDbTests.cpp"

class Main {
    TestRunner runner_;

public:
    Main(int argc, const char* argv[]) {
        runner_.Add(new TargetDbTests());
    }

    int Run() {
        return runner_.Run() ? 0 : 1;
    }
};

int main(int argc, const char* argv[]) {
    return Main(argc, argv).Run();
}
