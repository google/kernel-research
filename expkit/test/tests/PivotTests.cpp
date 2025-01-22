#pragma once

#include <cstdio>
#include "pivot/PivotFinder.cpp"
#include "test/TestSuite.cpp"
#include "util/Payload.cpp"

class PivotTests: public TestSuite {
public:
    PivotTests(): TestSuite("PivotStaticTests", "stack pivot static tests") { }

    TEST_METHOD(findsPivotsForLts6181, "find all pivots for LTS 6.1.81") {
        auto parser = KpwnParser::FromFile("test/artifacts/target_db_lts-6.1.81.kpwn");
        auto target = parser.GetTarget("kernelctf", "lts-6.1.81");
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

    TEST_METHOD(findsPivotForAllKernelCtfReleases, "finds the right pivots via RDI and RSI for all kernelCTF releases") {
        auto parser = KpwnParser::FromFile("test/artifacts/kernelctf.kpwn");
        auto targets = parser.GetAllTargets();
        if (targets.empty())
            Error("The database does not contain any targets.");

        for (auto target : targets) {
            for (auto buf_reg : std::vector<Register>{ Register::RDI, Register::RSI }) {
                Payload p(128);
                PivotFinder finder(target.pivots, buf_reg, p);
                if (!finder.Find().has_value())
                    Error("could not find stack pivot via %s register for target %s/%s", register_names[(int)buf_reg], target.distro.c_str(), target.release_name.c_str());
            }
        }
    }
};

class PivotKpwnTests: public TestSuite {
public:
    PivotKpwnTests(): TestSuite("PivotRuntimeTests", "stack pivot runtime tests") { }

    TEST_METHOD(pivotWinTargetTest, "call win_target via stack pivot") {
        Payload p(128);
        Register buf_reg = Register::RDI;

        PivotFinder finder(env->GetTarget().pivots, buf_reg, p);
        StackPivot pivot = finder.Find().value();
        Log("selected pivot: %s", pivot.GetDescription().c_str());

        auto& kpwn = env->GetKpwn();
        auto kaslr = kpwn.KaslrLeak();
        pivot.ApplyToPayload(p, kaslr);

        auto offs = pivot.GetDestinationOffset();
        p.Set(offs, kpwn.WinTarget());
        p.Set(offs + 8, kpwn.GetRipControlRecoveryAddr());

        auto buf_addr = kpwn.AllocBuffer(p.GetData(), true);
        kpwn.CallAddr(kaslr + pivot.GetGadgetOffset(), { { buf_reg, buf_addr } });
        kpwn.CheckWin();
        kpwn.Kfree(buf_addr);
    }
};