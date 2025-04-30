#pragma once

#include "test/TestUtils.cpp"
#include "test/kpwn/Kpwn.cpp"
#include "test/TestSuite.cpp"
#include "test/kpwn/kpwn.h"
#include "util/error.cpp"
#include "payloads/Payload.cpp"

class KpwnTests: public TestSuite {
    Kpwn* kpwn_;
public:
    KpwnTests(): TestSuite("KpwnRuntimeTests", "kpwn kernel module tests") { }

    void init() {
        kpwn_ = &env->GetKpwn();
    }

    TEST_METHOD(kaslrLeak, "can leak kASLR address") {
        uint64_t kaslr_min = 0xffffffff81000000;
        uint64_t kaslr_step = 0x200000;
        uint64_t kaslr_max = kaslr_min + 511 * kaslr_step;

        auto kaslr = kpwn_->KaslrLeak();

        ASSERT_MINMAX(kaslr_min, kaslr_max, kaslr);
        if ((kaslr & (kaslr_step - 1)) != 0)
            throw ExpKitError("invalid kASLR base address (%p), (kaslr & 0x%llx) == 0 should be true", kaslr, kaslr_step);
    }

    TEST_METHOD(bufferReadWrite, "can allocate, write and read buffers") {
        char data1[] = "hello world";
        char data2[] = "WORLD HELLO";
        std::vector<uint8_t> buf(32);

        memcpy(buf.data(), data1, sizeof(data1));
        auto buf_ptr = kpwn_->AllocBuffer(buf, true);
        auto readBuf1 = kpwn_->Read(buf_ptr, sizeof(data1));
        ASSERT_EQ((const char*) data1, (const char*) &*readBuf1.cbegin());

        memcpy(buf.data(), data2, sizeof(data2));
        kpwn_->Write(buf_ptr, buf);
        auto readBuf2 = kpwn_->Read(buf_ptr, sizeof(data2));
        ASSERT_EQ((const char*) data2, (const char*) &*readBuf2.cbegin());

        kpwn_->Kfree(buf_ptr);
    }

    TEST_METHOD(callWinTarget, "call win_target and check result") {
        kpwn_->CallAddr(kpwn_->WinTarget());
        kpwn_->CheckWin();
    }

    TEST_METHOD(kprobeTest, "kprobe test") {
        auto kprobe = kpwn_->InstallKprobe("__kmalloc", 2, CALL_LOG);
        auto buf_ptr = kpwn_->AllocBuffer(128, true);
        auto callLogs = kprobe->GetCallLogs(true);
        kpwn_->RemoveKprobe(kprobe);
        kpwn_->Kfree(buf_ptr);

        ASSERT_EQ(1, callLogs.size());
        ASSERT_EQ("__kmalloc", callLogs[0].function_name.c_str());
        ASSERT_EQ(2, callLogs[0].arguments.size());
        ASSERT_EQ(128, callLogs[0].arguments[0]);
        uint64_t GFP_ACCOUNT = 0x400000u;
        ASSERT_EQ(GFP_ACCOUNT, callLogs[0].arguments[1] & GFP_ACCOUNT);
    }

    TEST_METHOD(callMSleepTest, "call msleep rip control test") {
        auto msleep_addr = kpwn_->SymAddr("msleep");
        auto kprobe = kpwn_->InstallKprobe("msleep", 1, CALL_LOG);
        kpwn_->CallAddr(msleep_addr, { { Register::RDI, 10 } });
        auto callLogs = kprobe->GetCallLogs(true);
        kpwn_->RemoveKprobe(kprobe);

        ASSERT_EQ(1, callLogs.size());
        ASSERT_EQ("msleep", callLogs[0].function_name.c_str());
        ASSERT_EQ(1, callLogs[0].arguments.size());
        ASSERT_EQ(10, callLogs[0].arguments[0]);
    }

    TEST_METHOD(stackPivotRecoveryTest, "stack pivot recovery test") {
        auto win_target = kpwn_->WinTarget();
        auto rip_recovery = kpwn_->GetRipControlRecoveryAddr();
        Log("win_target = 0x%lx, rip_recovery = 0x%lx", win_target, rip_recovery);

        Payload p(256);
        p.Set(0, win_target);
        p.Set(8, rip_recovery);
        auto buf_addr = kpwn_->AllocBuffer(p.GetData(), true);
        Log("buf_addr = 0x%lx", buf_addr);

        kpwn_->SetRspAndRet(buf_addr);
        kpwn_->CheckWin();
        kpwn_->Kfree(buf_addr);
    }
};
