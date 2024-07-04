#pragma once

#define CHECK_ALLOC(x) ({ \
    typeof(x) __temp = (x); \
    if(!__temp) { \
        printk(KERN_ERR "kpwn: %s: " #x " returned 0.\n", __func__); \
        return -ERROR_ALLOC; \
    } \
    __temp; \
})

#define CHECK_ZERO(x, ERROR_CODE) ({ \
    typeof(x) __temp = (x); \
    if(__temp) { \
        printk(KERN_ERR "kpwn: %s: " #x " returned non-zero.\n", __func__); \
        return -ERROR_CODE; \
    } \
    __temp; \
})

#define STRUCT_FROM_USER(kernel_struct_ptr, user_ptr) CHECK_ZERO(copy_from_user(kernel_struct_ptr, user_ptr, sizeof(*kernel_struct_ptr)), ERROR_COPY_FROM_USER_STRUCT)
#define STRUCT_TO_USER(kernel_struct_ptr, user_ptr) CHECK_ZERO(copy_to_user(user_ptr, kernel_struct_ptr, sizeof(*kernel_struct_ptr)), ERROR_COPY_TO_USER_STRUCT)
#define DATA_FROM_USER(kernel_ptr, user_ptr, len) CHECK_ZERO(copy_from_user(kernel_ptr, user_ptr, len), ERROR_COPY_FROM_USER_DATA)
#define DATA_TO_USER(kernel_ptr, user_ptr, len) CHECK_ZERO(copy_to_user(user_ptr, kernel_ptr, len), ERROR_COPY_TO_USER_DATA);
