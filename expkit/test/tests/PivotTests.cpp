#pragma once

#include <cstdio>
#include "pivot/PivotFinder.cpp"
#include "test/TestSuite.cpp"
#include "test/TestUtils.cpp"
#include "util/Payload.cpp"

class PivotTests: public TestSuite {
public:
    PivotTests(): TestSuite("PivotTests", "kpwn db stack pivot tests") { }

    TEST_METHOD(findsPivotsForLts6181, "find all pivots for LTS 6.1.81") {
        auto target = env->GetKpwnParser().GetTarget("kernelctf", "lts-6.1.81");
        Payload p(128);
        for (int r = (int)Register::RAX; r <= (int)Register::R15; r++) {
            PivotFinder finder(target.pivots, (Register) r, p);
            auto pivots = finder.FindAll();
            Log("Found %lu pivots for %s", pivots.size(), register_names[r]);
            for (auto& pivot : pivots)
                Log(" - %s", pivot.GetDescription().c_str());
            Log("");
        }
    }

    TEST_METHOD(pivotWinTargetTest, "call win_target via stack pivot") {
        Payload p(128);
        Register buf_reg = Register::RDI;

        PivotFinder finder(env->GetTarget().pivots, buf_reg, p);
        StackPivot pivot = finder.Find().value();
        Log("selected pivot: %s", pivot.GetDescription().c_str());

        auto& kpwn = env->GetKpwn();
        auto kaslr = kpwn.KaslrLeak();
        pivot.ApplyToPayload(p);

        auto offs = pivot.GetDestinationOffset();
        p.Set(offs, kpwn.WinTarget());
        p.Set(offs + 8, kpwn.GetRipControlRecoveryAddr());

        auto buf_addr = kpwn.AllocBuffer(p.GetData(), true);
        kpwn.CallAddr(kaslr + pivot.GetGadgetOffset(), { { buf_reg, buf_addr } });
        kpwn.CheckWin();
        kpwn.Kfree(buf_addr);
    }
};