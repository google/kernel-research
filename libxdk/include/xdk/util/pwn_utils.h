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

#include <stdint.h>

/**
 * @defgroup util_classes Utility Classes
 * @brief Helper classes for various utilities.
 */

/**
 * @ingroup util_classes
 * @brief Checks if the provided address is a valid KASLR base address.
 *
 * @param kbase_addr The address to check.
 * @return True if the address is a valid KASLR base, false otherwise.
 */
bool is_kaslr_base(uint64_t kbase_addr);

/**
 * @ingroup util_classes
 * @brief Checks if the provided address is a valid KASLR base address.
 *
 * @param kbase_addr The address to check.
 * @return The checked KASLR base address if valid.
 */
uint64_t check_kaslr_base(uint64_t kbase_addr);

/**
 * @ingroup util_classes
 * @brief Checks if the provided address is a valid kernel heap pointer.
 *
 * @param heap_leak The address to check.
 * @return The checked kernel heap pointer if valid.
 */
uint64_t check_heap_ptr(uint64_t heap_leak);

/**
 * @ingroup util_classes
 * @brief Pins the calling thread to the specified CPU.
 *
 * @param cpu The CPU the calling thread should be pinned to.
 * @throws errno_error if the operation fails
 */
void pin_cpu(int cpu);

/**
 * @ingroup util_classes
 * @brief Leaks the KASLR base address using a prefetch side-channel.
 *
 * This function determines the kernel base address by measuring the execution
 * time of prefetch instructions across all possible KASLR slots. It uses a
 * "Windowed Max Absolute Difference" strategy, which detects the kernel image
 * location by sliding a window across the timing data to find the region that
 * maximizes the timing difference compared to the median. To ensure
 * reliability, it runs multiple independent scans and applies a majority voting
 * algorithm.
 *
 * @param window_size The size of the sliding window used to identify the region
 * containing the kernel image. This should match the number of pages the kernel
 * occupies in memory.
 * @param samples The number of prefetch timing measurements to collect for
 * each candidate KASLR slot during a single trial.
 * @param trials The number of memory scans to perform. The final result is
 * selected via a majority vote across these trials.
 * @return The kernel base address.
 * @throws ExpKitError if the address could not be leaked reliably.
 */
uint64_t leak_kaslr_base(uint64_t window_size, int samples = 100,
                         int trials = 7);