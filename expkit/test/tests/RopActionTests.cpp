#pragma once

#include <sys/wait.h>
#include "test/kpwn/Kpwn.cpp"
#include "test/TestSuite.cpp"
#include "util/HexDump.cpp"
#include "util/error.cpp"
#include "util/Payload.cpp"

class RopActionTests: public TestSuite {
    Kpwn* kpwn_;
public:
    RopActionTests(): TestSuite("RopActionRuntimeTests", "RopAction runtime tests") { }

    void init() {
        kpwn_ = &env->GetKpwn();
    }

    TEST_METHOD(teleforkTest, "tests if telefork works") {
        auto target = env->GetTarget();
        auto kaslr_base = kpwn_->KaslrLeak();
        auto rip_recovery = kpwn_->GetRipControlRecoveryAddr();
        auto orig_pid = getpid();

        RopChain rop(kaslr_base);
        target.AddRopAction(rop, RopActionId::TELEFORK, {2000});
        rop.Add(rip_recovery);

        Payload p(4096);
        auto rop_offs = p.Size() - rop.GetByteSize();
        p.Set(rop_offs, rop.GetData());

        auto buf_addr = kpwn_->AllocBuffer(p.GetData(), true);
        Log("buf_addr = 0x%lx", buf_addr);

        kpwn_->SetRspAndRet(buf_addr + rop_offs);
        if (getpid() != orig_pid) {
            printf("# child exited correctly\n");
            exit(0);
        }

        int status;
        if (wait(&status) == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
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