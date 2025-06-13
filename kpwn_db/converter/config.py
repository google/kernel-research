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
    SYM_FUNC | 0x07: "sock_def_write_space",
    SYM_FUNC | 0x08: "__sk_destruct",
    SYM_FUNC | 0x09: "rtnetlink_bind",

    # nm: D - initialized data section, global
    SYM_STRUCT | 0x01: "init_nsproxy",
    SYM_STRUCT | 0x02: "nft_last_type?",

    # nm: d - initialized data section, local
    SYM_OPS | 0x01: "anon_pipe_buf_ops",
    SYM_OPS | 0x02: "qfq_qdisc_ops",
    SYM_OPS | 0x03: "nft_last_ops?"
}

rop_actions = {
    0x01: "msleep(ARG_time_msec)",
    0x02: "commit_kernel_cred(prepare_kernel_cred(0))",
    0x03: "switch_task_namespaces(find_task_by_vpid(ARG_vpid=1), init_nsproxy)",
    0x04: "write_what_where_64(ARG_address, ARG_new_value)",
    0x05: "fork()",
    0x06: "telefork(ARG_sleep_msec=0xffffffff)",
    0x07: "ret_via_kpti_retpoline(ARG_user_rip, ARG_user_cs, ARG_user_rflags, ARG_user_sp, ARG_user_ss)",
}

structs = {
    "pipe_buffer": ["ops"],
    "pipe_buf_operations": ["release", "get"],
    "msg_msg": ["m_list.next", "m_list.prev", "m_type", "m_ts", "next", "security"],
    "msg_msgseg": ["next"],
    "hfsc_class": ["level", "cl_parent", "vt_node.__rb_parent_color",
                   "cf_node.__rb_parent_color", "cl_vt", "cl_cvtmin"],
    "simple_xattr": ["list.next?", "list.prev?", "rb_node.__rb_parent_color?",
                     "rb_node.rb_right?", "rb_node.rb_left?", "name", "size", "value"],
    "Qdisc_ops": ["change"],
    "sock": ["sk_destruct", "sk_rcu.next"],
    "netlink_sock": ["sk.sk_destruct", "sk.sk_rcu.next", "sk.sk_rcu.func", "netlink_bind", "sk.sk_write_space"],
    "nft_expr_ops?": ["dump?", "type?"],
    "nft_bitmap_elem?": [],
    "nft_set_elem_expr?": [],
    "nft_expr?": ["ops?"],
}
