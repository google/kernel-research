/*
 * Copyright 2024 Google LLC
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

#define LOG(msg, ...) printk(KERN_ERR "kpwn: " msg "\n" __VA_OPT__(,) __VA_ARGS__)

#define CHECK_ALLOC(x) ({ \
    typeof(x) __temp = (x); \
    if(!__temp) { \
        LOG("%s: " #x " returned 0.", __func__); \
        return -ERROR_ALLOC; \
    } \
    __temp; \
})

#define CHECK_ZERO_NO_RET(x) ({ \
    typeof(x) __temp = (x); \
    if(__temp) \
        LOG("%s: " #x " returned non-zero (%ld).", __func__, (long int) __temp); \
    __temp; \
})

#define CHECK_ZERO(x, ERROR_CODE) ({ \
    typeof(x) __temp = (x); \
    if(__temp) { \
        LOG("%s: " #x " returned non-zero.", __func__); \
        return -ERROR_CODE; \
    } \
    __temp; \
})

#define STRUCT_FROM_USER(kernel_struct_ptr, user_ptr) CHECK_ZERO(copy_from_user(kernel_struct_ptr, user_ptr, sizeof(*kernel_struct_ptr)), ERROR_COPY_FROM_USER_STRUCT)
#define STRUCT_TO_USER(kernel_struct_ptr, user_ptr) CHECK_ZERO(copy_to_user(user_ptr, kernel_struct_ptr, sizeof(*kernel_struct_ptr)), ERROR_COPY_TO_USER_STRUCT)
#define DATA_FROM_USER(kernel_ptr, user_ptr, len) CHECK_ZERO(copy_from_user(kernel_ptr, user_ptr, len), ERROR_COPY_FROM_USER_DATA)
#define DATA_TO_USER(kernel_ptr, user_ptr, len) CHECK_ZERO(copy_to_user(user_ptr, kernel_ptr, len), ERROR_COPY_TO_USER_DATA);
#define STRING_FROM_USER(kernel_buf, user_ptr) CHECK_ALLOC(strncpy_from_user(kernel_buf, user_ptr, ARRAY_SIZE(kernel_buf)))
