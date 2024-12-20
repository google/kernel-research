"""Module containing the configuration for generating the kpwn DB."""
SYM_FUNC   = 0x01000000
SYM_STRUCT = 0x02000000
SYM_OPS    = 0x03000000

symbols = {
    # nm: T - text (code) section, global
    SYM_FUNC | 0x01: "prepare_kernel_cred",
    SYM_FUNC | 0x02: "commit_creds",
    SYM_FUNC | 0x03: "find_task_by_vpid",
    SYM_FUNC | 0x04: "switch_task_namespaces",
    SYM_FUNC | 0x05: "__x64_sys_fork",
    SYM_FUNC | 0x06: "msleep",

    # nm: D - initialized data section, global
    SYM_STRUCT | 0x01: "init_nsproxy",

    # nm: d - initialized data section, local
    SYM_OPS | 0x01: "anon_pipe_buf_ops"
}

rop_actions = {
    0x01: "msleep(ARG_time_msec)",
    0x02: "commit_kernel_cred(prepare_kernel_cred(0))",
    0x03: "switch_task_namespaces(find_task_by_vpid(1), init_nsproxy)",
    0x04: "core_pattern_overwrite(ARG_first_8_bytes)",
    0x05: "core_pattern_overwrite(ARG_first_8_bytes, ARG_second_8_bytes)",
}
