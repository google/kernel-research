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

#include <sched.h>
#include <stdint.h>
#include <xdk/util/error.h>
#include <xdk/util/pwn_utils.h>

bool is_kaslr_base(uint64_t kbase_addr) {
    if ((kbase_addr & 0xFFFF0000000FFFFF) != 0xFFFF000000000000)
        return false;
    return true;
}

uint64_t check_kaslr_base(uint64_t kbase_addr) {
    if (!is_kaslr_base(kbase_addr))
        throw ExpKitError("kernel base address (%p) is incorrect", kbase_addr);
    return kbase_addr;
}

uint64_t check_heap_ptr(uint64_t heap_leak) {
    if ((heap_leak & 0xFFFF000000000000) != 0xFFFF000000000000)
        throw ExpKitError("kernel heap address (%p) is incorrect", heap_leak);
    return heap_leak;
}

void pin_cpu(int cpu) {
    cpu_set_t set;
    CPU_ZERO(&set);
    CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set))
        throw errno_error("sched_setaffinity failed");
}