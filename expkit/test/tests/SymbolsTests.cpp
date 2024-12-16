#pragma once

#include <cstdio>
#include "target/KpwnParser.cpp"
#include "test/TestSuite.cpp"
#include "test/TestUtils.cpp"
#include "test/kpwn/Kpwn.cpp"
#include "util/file.cpp"
#include "util/str.cpp"

class SymbolsTest: public TestSuite {
public:
    SymbolsTest(): TestSuite("SymbolsTest", "kpwn db symbols tests") { }

    TEST_METHOD(symbolsCheck, "check if the database contains the correct symbols") {
        auto kaslr_base = env->GetKpwn().KaslrLeak();

        for (auto pair : symbol_names) {
            std::string func_name(pair.second);
            tolower(func_name);
            TestUtils::eq(env->GetKpwn().SymAddr(func_name.c_str()) - kaslr_base,
                env->GetTarget().GetSymbolOffset(pair.first), pair.second);
        }
    }
};