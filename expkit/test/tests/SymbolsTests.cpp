#pragma once

#include <cstdio>
#include "target/KpwnParser.cpp"
#include "test/TestSuite.cpp"
#include "test/TestUtils.cpp"
#include "test/kpwn/Kpwn.cpp"
#include "util/file.cpp"
#include "util/str.cpp"

class SymbolsTest: public TestSuite {
    Kpwn* kpwn_;
    KpwnParser* parser_;
    Target target_;

public:
    SymbolsTest(): TestSuite("SymbolsTest", "kpwn db symbols tests") { }

    void init() {
        parser_ = new KpwnParser(read_file("test/artifacts/target_db_lts-6.1.81.kpwn"));
        target_ = parser_->AutoDetectTarget();
        kpwn_ = new Kpwn();
    }

    TEST_METHOD(symbolsCheck, "check if the database contains the correct symbols") {
        auto kaslr_base = kpwn_->KaslrLeak();

        for (auto pair : symbol_names) {
            std::string func_name(pair.second);
            tolower(func_name);
            TestUtils::eq(kpwn_->SymAddr(func_name.c_str()) - kaslr_base,
                target_.GetSymbolOffset(pair.first), pair.second);
        }
    }
};