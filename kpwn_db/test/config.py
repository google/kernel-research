"""Module containing the configuration for generating the kpwn DB."""
symbols = [
    # nm: T - text (code) section, global
    "prepare_kernel_cred",
    "commit_creds",
    "find_task_by_vpid",
    "switch_task_namespaces",
    "__x64_sys_fork",
    "msleep",

    # nm: D - initialized data section, global
    "init_nsproxy",

    # nm: d - initialized data section, local
    "anon_pipe_buf_ops",
]

rop_actions = [
    "msleep(ARG_time_msec)",
    "commit_kernel_cred(prepare_kernel_cred(0))",
    "switch_task_namespaces(find_task_by_vpid(ARG_vpid=1), init_nsproxy)",
    "write_what_where_64(ARG_address, ARG_new_value)",
    "fork()",
    "telefork(ARG_sleep_msec=0xffffffff)",
    "ret_via_kpti_retpoline(ARG_user_rip, ARG_user_cs, ARG_user_rflags, ARG_user_sp, ARG_user_ss)",
]

structs = {
    "pipe_buffer": ["ops"],
    "pipe_buf_operations": ["release", "get"],
    "msg_msg": ["m_list.next", "m_list.prev", "m_type", "m_ts", "next", "security"],
    "msg_msgseg": ["next"],
    "hfsc_class": ["level", "cl_parent", "vt_node.__rb_parent_color?",
                   "cf_node.__rb_parent_color?", "cl_vt", "cl_cvtmin"],
}
