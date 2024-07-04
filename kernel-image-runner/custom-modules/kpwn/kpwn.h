#define DEVICE_NAME "kpwn"

typedef struct kpwn_message {
    uint64_t length;
    uint8_t* data;
    union {
        uint64_t kernel_addr;
        void* kernel_ptr;
    };
    uint8_t gfp_account;
} kpwn_message;

enum kpwn_cmd { ALLOC_BUFFER = 0x1000, KFREE, KASLR_LEAK, WIN_TARGET, RIP_CONTROL, ARB_READ, ARB_WRITE };

enum kpwn_errors {
    SUCCESS = 0,
    ERROR_GENERIC = 0x1000,
    ERROR_UNKNOWN_COMMAND = 0x1001,
    ERROR_ALLOC = 0x1002,
    ERROR_COPY_FROM_USER_STRUCT = 0x1003,
    ERROR_COPY_FROM_USER_DATA = 0x1004,
    ERROR_COPY_TO_USER_STRUCT = 0x1005,
    ERROR_COPY_TO_USER_DATA = 0x1006,
};

enum regs_to_set: unsigned long {
    RAX = 0x000001,
    RBX = 0x000002,
    RCX = 0x000004,
    RDX = 0x000008,
    RSI = 0x000010,
    RDI = 0x000020,
    RBP = 0x000040,
    RSP = 0x000080,
    R8  = 0x000100,
    R9  = 0x000200,
    R10 = 0x000400,
    R11 = 0x000800,
    R12 = 0x001000,
    R13 = 0x002000,
    R14 = 0x004000,
    //R15 = 0x008000,
    ALL = 0xffffffff,
};

enum rip_action {
    JMP_RIP = 0x1, // jmp r15 (r15 == rip_control_args.rip)
    CALL_RIP = 0x2, // call r15 (r15 == rip_control_args.rip)
    RET = 0x3,
    NONE = 0x4,
};

typedef struct {
    // 0x00
    uint64_t rax, rbx, rcx, rdx;
    // 0x20
    uint64_t rsi, rdi, rbp, rsp;
    // 0x40
    uint64_t r8,  r9,  r10, r11;
    // 0x60
    uint64_t r12, r13, r14, r15;
    // 0x80
    uint64_t rip;
    // 0x88
    uint64_t regs_to_set;
    // 0x90
    uint64_t action;
} rip_control_args;

