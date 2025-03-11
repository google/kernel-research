#ifndef PAYLOAD_BUILDER_H
#define PAYLOAD_BUILDER_H

#include <vector>
#include <optional>
#include <cstdint>
#include <tuple>

#include "util/Register.cpp"

#include "Payload.cpp"
#include "RopChain.cpp"

// TODO we could also know a buffer's address?

struct PayloadData {
    Payload& payload;
    const std::vector<Register> registers;
    const std::optional<size_t> next_rip_offset;

    PayloadData(Payload &payload_ref,
                const std::vector<Register> &regs = {},
                std::optional<size_t> offset = std::nullopt)
        : payload(payload_ref), registers(regs), next_rip_offset(offset)
    {
    }
};

class PayloadBuilder {
  public:
    PayloadBuilder(const Pivots &pivots, uint64_t kaslr_base) : pivots_(pivots), kaslr_base_(kaslr_base){}

    void AddPayload(Payload& payload,
                    const std::vector<Register>& registers = {},
                    std::optional<size_t> next_rip_offset = std::nullopt);

    void AddPayload(Payload& payload,
                    std::optional<Register> reg = std::nullopt,
                    std::optional<size_t> next_rip_offset = std::nullopt);

    void AddRopChain(const RopChain& rop_chain);

    // Build the final payload.
    bool build(bool need_pivot = true);

    std::string GetDescription();

  private:

    bool TryPayloadPivot(Payload& payload, StackPivot pivot);

    uint64_t EstimatePayloadSpaceAfter(Payload& payload, uint64_t offset);

    std::vector<PayloadData> payload_datas_;
    std::vector<RopAction> rop_actions_;
    Pivots pivots_;
    uint64_t kaslr_base_;
    std::optional<StackPivot> chosen_pivot_;
    std::optional<Payload> chosen_payload_;
    std::vector<StackShiftingInfo> chosen_shifts_;
};

#endif // PAYLOAD_BUILDER_H