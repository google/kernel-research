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
    SymbolsTest(): TestSuite("SymbolsRuntimeTests", "kpwn db symbols tests") { }

    TEST_METHOD(symbolsCheck, "check if the database contains the correct symbols") {
        auto kaslr_base = env->GetKpwn().KaslrLeak();

        for (auto pair : env->GetTarget().symbols) {
            auto sym_addr = env->GetKpwn().SymAddrOpt(pair.first.c_str());

            // releases without CONFIG_KALLSYMS_ALL only contain function addresses
            if (sym_addr.has_value())
                TestUtils::eq(sym_addr.value() - kaslr_base, pair.second, pair.first.c_str());
        }
    }
};