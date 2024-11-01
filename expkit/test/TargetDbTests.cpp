#pragma once

#include <algorithm>
#include <cstdio>
#include "test/TestUtils.cpp"
#include "test/TestSuite.cpp"
#include "target/KpwnParser.cpp"
#include "target/Target.cpp"
#include "util/file.cpp"

struct TargetDbTests: TestSuite {
    std::vector<uint8_t> kpwn_db_lts6181;

    TargetDbTests(): TestSuite("TargetDbTests", "target.kpwn database tests") { }

    void init() {
        kpwn_db_lts6181 = read_file("test/artifacts/target_db_lts-6.1.81.kpwn");
    }

    KpwnParser getParser() {
        auto parser = KpwnParser(kpwn_db_lts6181);
        parser.SetLog(this);
        return parser;
    }

    Target getLts6181() {
        return getParser().GetTarget("kernelctf", "lts-6.1.81");
    }

    TEST_METHOD(versionLts6181, "version, distro and release_name fields are correct in target db (lts-6.1.81)") {
        const char* expected_version = "Linux version 6.1.81 (runner@fv-az736-920) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP PREEMPT_DYNAMIC Thu Mar  7 12:17:31 UTC 2024";
        auto parser = getParser();
        auto target = getLts6181();
        ASSERT_EQ(expected_version, target.version.c_str());

        auto target2 = parser.GetTarget(expected_version);
        ASSERT_EQ("kernelctf", target2.distro.c_str());
        ASSERT_EQ("lts-6.1.81", target2.release_name.c_str());
    }

    TEST_METHOD(symbolsLts6181, "symbols are correct in target db (lts-6.1.81)") {
        auto target = getLts6181();
        ASSERT_EQ(0x1be800, target.GetSymbolOffset(PREPARE_KERNEL_CRED));
        ASSERT_EQ(0x2876880, target.GetSymbolOffset(INIT_NSPROXY));
        ASSERT_EQ(0x1a200c0, target.GetSymbolOffset(ANON_PIPE_BUF_OPS));
        ASSERT_EQ(0x227a50, target.GetSymbolOffset(MSLEEP));
    }
};