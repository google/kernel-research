#pragma once

#include "test/TestUtils.h"
#include "test/TestSuite.h"
#include <kernelXDK/util/error.h>
#include <kernelXDK/payloads/Payload.h>
#include <kernelXDK/xdk_device/xdk_device.h>

class XdkDeviceTests: public TestSuite {
    XdkDevice* xdk_;
public:
    XdkDeviceTests(): TestSuite("XdkDeviceRuntimeTests", "xdk kernel module tests") { }

    void init() {
        xdk_ = &env->GetXdkDevice();
    }

    TEST_METHOD(kaslrLeak, "can leak kASLR address") {
        uint64_t kaslr_min = 0xffffffff81000000;
        uint64_t kaslr_step = 0x200000;
        uint64_t kaslr_max = kaslr_min + 511 * kaslr_step;

        auto kaslr = xdk_->KaslrLeak();

        ASSERT_MINMAX(kaslr_min, kaslr_max, kaslr);
        if ((kaslr & (kaslr_step - 1)) != 0)
            throw ExpKitError("invalid kASLR base address (%p), (kaslr & 0x%llx) == 0 should be true", kaslr, kaslr_step);
    }

    TEST_METHOD(bufferReadWrite, "can allocate, write and read buffers") {
        char data1[] = "hello world";
        char data2[] = "WORLD HELLO";
        std::vector<uint8_t> buf(32);

        memcpy(buf.data(), data1, sizeof(data1));
        auto buf_ptr = xdk_->AllocBuffer(buf, true);
        auto readBuf1 = xdk_->Read(buf_ptr, sizeof(data1));
        ASSERT_EQ((const char*) data1, (const char*) &*readBuf1.cbegin());

        memcpy(buf.data(), data2, sizeof(data2));
        xdk_->Write(buf_ptr, buf);
        auto readBuf2 = xdk_->Read(buf_ptr, sizeof(data2));
        ASSERT_EQ((const char*) data2, (const char*) &*readBuf2.cbegin());

        xdk_->Kfree(buf_ptr);
    }

    TEST_METHOD(callWinTarget, "call win_target and check result") {
        xdk_->CallAddr(xdk_->WinTarget());
        xdk_->CheckWin();
    }

    TEST_METHOD(kprobeTest, "kprobe test") {
        auto kprobe = xdk_->InstallKprobe("__kmalloc", 2, CALL_LOG);
        auto buf_ptr = xdk_->AllocBuffer(128, true);
        auto callLogs = kprobe->GetCallLogs(true);
        xdk_->RemoveKprobe(kprobe);
        xdk_->Kfree(buf_ptr);

        ASSERT_EQ(1, callLogs.size());
        ASSERT_EQ("__kmalloc", callLogs[0].function_name.c_str());
        ASSERT_EQ(2, callLogs[0].arguments.size());
        ASSERT_EQ(128, callLogs[0].arguments[0]);
        uint64_t GFP_ACCOUNT = 0x400000u;
        ASSERT_EQ(GFP_ACCOUNT, callLogs[0].arguments[1] & GFP_ACCOUNT);
    }

    TEST_METHOD(callMSleepTest, "call msleep rip control test") {
        auto msleep_addr = xdk_->SymAddr("msleep");
        auto kprobe = xdk_->InstallKprobe("msleep", 1, CALL_LOG);
        xdk_->CallAddr(msleep_addr, { { Register::RDI, 10 } });
        auto callLogs = kprobe->GetCallLogs(true);
        xdk_->RemoveKprobe(kprobe);

        ASSERT_EQ(1, callLogs.size());
        ASSERT_EQ("msleep", callLogs[0].function_name.c_str());
        ASSERT_EQ(1, callLogs[0].arguments.size());
        ASSERT_EQ(10, callLogs[0].arguments[0]);
    }

    TEST_METHOD(stackPivotRecoveryTest, "stack pivot recovery test") {
        auto win_target = xdk_->WinTarget();
        auto rip_recovery = xdk_->GetRipControlRecoveryAddr();
        Log("win_target = 0x%lx, rip_recovery = 0x%lx", win_target, rip_recovery);

        Payload p(256);
        p.Set(0, win_target);
        p.Set(8, rip_recovery);
        p.Set(16, 0xffffffff41414141); // crash if rip_recovery fails
        auto buf_addr = xdk_->AllocBuffer(p.GetData(), true);
        Log("buf_addr = 0x%lx", buf_addr);

        xdk_->SetRspAndRet(buf_addr);
        xdk_->CheckWin();
        xdk_->Kfree(buf_addr);
    }
};
