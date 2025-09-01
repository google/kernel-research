# Copyright 2025 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Module containing the configuration for generating the kxdb DB."""

symbols = [
    # nm: T - text (code) section, global
    "prepare_kernel_cred",
    "commit_creds",
    "find_task_by_vpid",
    "switch_task_namespaces",
    "__x64_sys_fork",
    "msleep",
    "sock_def_write_space",
    "__sk_destruct",
    "rtnetlink_bind",

    # nm: D - initialized data section, global
    "init_nsproxy",
    "nft_last_type",

    # nm: d - initialized data section, local
    "anon_pipe_buf_ops",
    "qfq_qdisc_ops",
    "nft_last_ops"
]

rop_actions = [
    "msleep(ARG_time_msec)",
    "commit_creds(prepare_kernel_cred(&init_task))",
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
    "hfsc_class": ["level", "cl_parent", "vt_node.__rb_parent_color",
                   "cf_node.__rb_parent_color", "cl_vt", "cl_cvtmin"],
    "simple_xattr": ["list.next?", "list.prev?", "rb_node.__rb_parent_color?",
                     "rb_node.rb_right?", "rb_node.rb_left?", "name", "size", "value"],
    "Qdisc_ops": ["change"],
    "sock": ["sk_destruct", "sk_rcu.next"],
    "netlink_sock": ["sk.sk_destruct", "sk.sk_rcu.next", "sk.sk_rcu.func", "netlink_bind", "sk.sk_write_space"],
    "nft_expr_ops": ["dump?", "type?"],
    "nft_bitmap_elem": [],
    "nft_set_elem_expr": [],
    "nft_expr": ["ops?"],
}
