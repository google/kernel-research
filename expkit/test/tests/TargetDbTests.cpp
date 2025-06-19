#pragma once

#include <cstdio>
#include "test/TestUtils.cpp"
#include "test/TestSuite.cpp"
#include "target/KpwnParser.hpp"
#include "target/Target.hpp"
#include "target/TargetDb.hpp"
#include "payloads/RopChain.h"
#include "util/file.cpp"

struct TargetDbTests: TestSuite {
    std::vector<uint8_t> kpwn_db_lts6181;

    TargetDbTests(): TestSuite("TargetDbStaticTests", "target.kpwn database tests") { }

    const char* lts_6181_version = "Linux version 6.1.81 (runner@fv-az736-920) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #1 SMP PREEMPT_DYNAMIC Thu Mar  7 12:17:31 UTC 2024";

    void init() {
        kpwn_db_lts6181 = read_file("test/artifacts/target_db_lts-6.1.81.kpwn");
    }

    KpwnParser getParser() {
        auto parser = KpwnParser(kpwn_db_lts6181);
        parser.SetLog(this);
        return parser;
    }

    Target getLts6181() {
        return getParser().GetTarget("kernelctf", "lts-6.1.81", true).value();
    }

    TEST_METHOD(versionLts6181, "version, distro and release_name fields are correct in target db (lts-6.1.81)") {
        auto parser = getParser();
        auto target = getLts6181();
        ASSERT_EQ(lts_6181_version, target.version.c_str());

        auto target2 = parser.GetTarget(lts_6181_version, true).value();
        ASSERT_EQ("kernelctf", target2.distro.c_str());
        ASSERT_EQ("lts-6.1.81", target2.release_name.c_str());
    }

    TEST_METHOD(symbolsLts6181, "symbols are correct in target db (lts-6.1.81)") {
        auto target = getLts6181();
        ASSERT_EQ(0x1be800, target.GetSymbolOffset("prepare_kernel_cred"));
        ASSERT_EQ(0x2876880, target.GetSymbolOffset("init_nsproxy"));
        ASSERT_EQ(0x1a200c0, target.GetSymbolOffset("anon_pipe_buf_ops"));
        ASSERT_EQ(0x227a50, target.GetSymbolOffset("msleep"));
    }

    TEST_METHOD(metaDataIsNotParsedByDefault, "metadata is not parsed by default") {
        auto parser = getParser();
        parser.ParseHeader();
        ASSERT_EQ(0, parser.rop_action_meta_.size());
    }

    TEST_METHOD(ropActionsMetaLts6181, "rop actions metadata is correct (lts-6.1.81)") {
        auto parser = getParser();
        parser.ParseHeader(true);
        ASSERT_EQ(7, parser.rop_action_meta_.size());
        auto& msleep_meta = parser.rop_action_meta_[RopActionId::MSLEEP];
        ASSERT_EQ(RopActionId::MSLEEP, msleep_meta.type_id);
        ASSERT_EQ("msleep(ARG_time_msec)", msleep_meta.desc.c_str());
        ASSERT_EQ(1, msleep_meta.args.size());
        ASSERT_EQ("time_msec", msleep_meta.args[0].name.c_str());
        ASSERT_EQ(true, msleep_meta.args[0].required);
        ASSERT_EQ(0, msleep_meta.args[0].default_value);
    }

    TEST_METHOD(ropActionsLts6181, "rop actions are correct (lts-6.1.81)") {
        auto target = getLts6181();

        auto& telefork = target.rop_actions[RopActionId::TELEFORK];
        ASSERT_EQ(4, telefork.size());
        ASSERT_EQ(RopItemType::SYMBOL, telefork[0].type);
        ASSERT_EQ(0x18f0d0 /* FORK */, telefork[0].value);
        ASSERT_EQ(RopItemType::SYMBOL, telefork[1].type);
        ASSERT_EQ(0x21f5 /* POP_RDI */, telefork[1].value);
        ASSERT_EQ(RopItemType::ARGUMENT, telefork[2].type);
        ASSERT_EQ(0, telefork[2].value);
        ASSERT_EQ(RopItemType::SYMBOL, telefork[3].type);
        ASSERT_EQ(0x227a50 /* MSLEEP */, telefork[3].value);
    }

    TEST_METHOD(ropChainLts6181, "rop chain generation is correct (lts-6.1.81)") {
        auto target = getLts6181();

        auto kaslr_base = 0x100000000ul;
        RopChain rop(target, kaslr_base);
        rop.AddRopAction(RopActionId::TELEFORK, { 5000 });

        std::vector<RopAction> actions = rop.GetActions();
        ASSERT_EQ(1, actions.size());
        ASSERT_EQ(4, actions[0].values.size());
        ASSERT_EQ(kaslr_base + 0x18f0d0 /* FORK */, actions[0].values[0]);
        ASSERT_EQ(kaslr_base + 0x21f5 /* POP_RDI */, actions[0].values[1]);
        ASSERT_EQ(5000 /* time_msec */, actions[0].values[2]);
        ASSERT_EQ(kaslr_base + 0x227a50 /* MSLEEP */, actions[0].values[3]);
    }

    TEST_METHOD(pivotsLts6181, "stack pivots are correct (lts-6.1.81)") {
        auto pivots = getLts6181().pivots;
        ASSERT_EQ(6, pivots.one_gadgets.size());
        ASSERT_EQ(187, pivots.push_indirects.size());
        ASSERT_EQ(3, pivots.pop_rsps.size());

        auto& g1 = pivots.one_gadgets[0];
        ASSERT_EQ(0x840463, g1.address);
        ASSERT_EQ(Register::RBP, g1.pivot_reg.reg);
        ASSERT_EQ(0, g1.pivot_reg.used_offsets.size());
        ASSERT_EQ(8, g1.next_rip_offset);

        auto& g2 = pivots.push_indirects[0];
        ASSERT_EQ(0xcbbce1, g2.address);
        ASSERT_EQ(IndirectType::CALL, g2.indirect_type);
        ASSERT_EQ(Register::R11, g2.push_reg.reg);
        ASSERT_EQ(Register::R13, g2.indirect_reg.reg);
        ASSERT_EQ(72, g2.next_rip_offset);

        auto& g3 = pivots.pop_rsps[0];
        ASSERT_EQ(0x12c7be, g3.address);
        ASSERT_EQ(0, g3.stack_change_before_rsp);
        ASSERT_EQ(8, g3.next_rip_offset);
    }

    TEST_METHOD(structLts6181, "structs are correct (lts-6.1.81)") {
        auto structs = getLts6181().structs;
        ASSERT_MINMAX(7, 999, (int)structs.size());

        ASSERT_EQ(40, structs["pipe_buffer"].size);
        ASSERT_EQ(1, structs["pipe_buffer"].fields.size());
        ASSERT_EQ(16, structs["pipe_buffer"].fields["ops"].offset);
        ASSERT_EQ(8, structs["pipe_buffer"].fields["ops"].size);

        ASSERT_EQ(48, structs["msg_msg"].size);
        ASSERT_EQ(6, structs["msg_msg"].fields.size());
        ASSERT_EQ(32, structs["msg_msg"].fields["next"].offset);
        ASSERT_EQ(8, structs["msg_msg"].fields["next"].size);

        ASSERT_EQ(8, structs["msg_msgseg"].size);

        ASSERT_EQ(752, structs["hfsc_class"].size);
        ASSERT_EQ(312, structs["hfsc_class"].fields["cl_cvtmin"].offset);
    }

    TEST_METHOD(targetDbMergingWorks, "TargetDb can merge db with static targets") {
        TargetDb db(getParser());

        StaticTarget st("kernelctf", "lts-6.1.81");
        st.AddSymbol("new_symbol", 0x1234);
        st.AddStruct("new_struct", 80, { { "field1", 0x10, 8 }, { "field2", 0x20, 8 } });
        db.AddStaticTarget(st);

        auto target = db.GetTarget(lts_6181_version);
        // symbols from the kpwn db found
        ASSERT_EQ(0x1be800, target.GetSymbolOffset("prepare_kernel_cred"));
        // symbols from the static target also found
        ASSERT_EQ(0x1234, target.GetSymbolOffset("new_symbol"));
        ASSERT_EQ(0x20, target.structs.at("new_struct").fields.at("field2").offset);
    }

    TEST_METHOD(staticDbWorks, "TargetDb can work with only static targets without a db") {
        TargetDb db;

        StaticTarget st("kernelctf", "lts-6.1.81", lts_6181_version);
        st.AddSymbol("new_symbol", 0x1234);
        db.AddStaticTarget(st);

        auto target = db.GetTarget(lts_6181_version);
        ASSERT_EQ("lts-6.1.81", target.release_name.c_str());
        ASSERT_EQ(0x1234, target.GetSymbolOffset("new_symbol"));
    }
};
