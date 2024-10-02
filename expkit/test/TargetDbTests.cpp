#pragma once

#include <cstdio>
#include "test/TestUtils.cpp"
#include "test/TestSuite.cpp"
#include "target/KpwnParser.cpp"
#include "target/Target.cpp"

struct TargetDbTests: TestSuite {
    TargetDbTests(): TestSuite("TargetDbTests", "target.kpwn database tests") {
        tests.push_back(Test("parseTestLts6181", "db parsing test for kernelCTF lts-6.1.81", [this]() { parseTestLts6181(); }));
    }

    void parseTestLts6181() {
        auto parser = KpwnParser::FromFile("test/artifacts/target_db_lts-6.1.81.kpwn");
        parser.SetLog(this);
        auto target = parser.GetTarget("kernelctf", "lts-6.1.81");
        auto target2 = parser.GetTarget("Linux version 6.1.81 (runner@fv-az736-920) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP PREEMPT_DYNAMIC Thu Mar  7 12:17:31 UTC 2024");
        TestUtils::eq(0x1be800, target.GetSymbolOffset(PREPARE_KERNEL_CRED), "PREPARE_KERNEL_CRED");
        TestUtils::eq(0x2876880, target.GetSymbolOffset(INIT_NSPROXY), "INIT_NSPROXY");
        TestUtils::eq(0x1a200c0, target.GetSymbolOffset(ANON_PIPE_BUF_OPS), "ANON_PIPE_BUF_OPS");
    }
};