#pragma once

#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include "./kpwn.h"
#include "util/error.cpp"
#include "util/syscalls.cpp"
#include "util/Register.cpp"

#define DEVICE_PATH "/dev/kpwn"

enum class RipAction { Jmp = 0x1, Call = 0x2, Ret = 0x3 };

struct CallLog {
    std::string function_name;
    std::vector<uint64_t> arguments;
    uint64_t return_value;
    std::string call_stack;

    std::string GetSummary() {
        std::string probe_str;
        for (auto arg : arguments)
            probe_str += format_str("%s0x%lx", probe_str.size() == 0 ? "" : ", ", arg);
        return format_str("%s(%s) = 0x%lx", function_name, probe_str.c_str(), return_value);
    }
};

class Kpwn;

class Kprobe {
    kprobe_args args_;
    const size_t logs_size = 16 * 4096;
public:
    Kprobe(const char* function_name, uint8_t arg_count = 0, enum kprobe_log_mode log_mode = (kprobe_log_mode)(ENTRY_WITH_CALLSTACK | RETURN), const char* log_call_stack_filter = nullptr) {
        args_ = { .pid_filter = getpid(), .arg_count = arg_count, .log_mode = (uint8_t) log_mode, .logs = 0 };
        strcpy(args_.function_name, function_name);
        if (args_.log_mode & CALL_LOG) {
            if (log_call_stack_filter)
                strncpy(args_.log_call_stack_filter, log_call_stack_filter, sizeof(args_.log_call_stack_filter));

            kprobe_log* log = (kprobe_log*) mmap(NULL, logs_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            log->struct_size = logs_size;
            log->missed_logs = 0;
            log->next_offset = 0;
            log->entry_count = 0;
            args_.logs = log;
        }
    }

    std::vector<CallLog> GetCallLogs(bool clear_log = false) {
        std::vector<CallLog> result;

        kprobe_log_entry* entry = args_.logs->entries;
        for (int i = 0; i < args_.logs->entry_count; i++) {
            CallLog log;
            log.function_name = args_.function_name;
            for (int j = 0; j < args_.arg_count; j++)
                log.arguments.push_back((uint64_t) entry->arguments[j]);
            log.return_value = entry->return_value;
            log.call_stack = std::string((char*)entry->call_stack, entry->call_stack_size);
            result.push_back(log);

            entry = (kprobe_log_entry*)(((uint8_t*) entry) + entry->entry_size);
        }

        if (clear_log) {
            args_.logs->entry_count = 0;
            args_.logs->next_offset = 0;
            args_.logs->missed_logs = 0;
        }

        return result;
    }

    void PrintCallLog(bool clear_log = false) {
        auto callLogs = GetCallLogs(clear_log);

        printf("%s call log (count = %lu):\n", args_.function_name, callLogs.size());

        int i = 0;
        for (auto callLog : callLogs)
            printf("  #%d: %s\n      call stack: %s\n",
                i++, callLog.GetSummary().c_str(), callLog.call_stack.c_str());
    }

    ~Kprobe() {
        if (args_.logs)
            munmap(args_.logs, args_.logs->struct_size);
    }

    friend class Kpwn;
};

class Kpwn {
    int fd_;
    enum kprobe_log_mode default_log_mode_ = (kprobe_log_mode)(ENTRY_WITH_CALLSTACK | RETURN);
    int call_log_capacity_ = 50;
    std::set<Kprobe*> installed_probes_;

    rip_control_args ConvertRipArgs(RipAction action, const std::map<Register, uint64_t>& regs = {}) {
        rip_control_args args = { 0 };
        args.action = (uint64_t) action;

        for (const auto& regp : regs) {
            ((uint64_t*)&args)[(uint)regp.first] = regp.second;
            args.regs_to_set |= 1 << (uint)regp.first;
        }

        return args;
    }

    kpwn_error CallRaw(enum kpwn_cmd cmd, void* arg) const {
        kpwn_error error_code = (kpwn_error) -::ioctl(fd_, cmd, arg);
        if (error_code == SUCCESS || ERROR_GENERIC <= error_code && error_code <= ERROR_UNKNOWN_SYMBOL) return error_code;
        throw ExpKitError("kpwn command %s failed with unknown error code 0x%x");
    }

public:
    static bool IsAvailable() {
        return access(DEVICE_PATH, F_OK) != -1;
    }

    Kpwn() {
        fd_ = Syscalls::open("/dev/kpwn", O_RDWR);
    }

    kpwn_error Call(enum kpwn_cmd cmd, void* arg, kpwn_error expected_error) const {
        auto error = CallRaw(cmd, arg);
        if (error != SUCCESS && error != expected_error)
            throw ExpKitError("kpwn command %s failed with error code 0x%x (%s)", kpwn_cmd_names[cmd - 0x1000], error,
                kpwn_errors_names[error - ERROR_GENERIC]);
        return error;
    }

    void Call(enum kpwn_cmd cmd, void* arg) const {
        Call(cmd, arg, SUCCESS);
    }

    uint64_t AllocBuffer(uint64_t size, bool gfp_account) const {
        kpwn_message msg = { .length = size, .gfp_account = gfp_account };
        Call(ALLOC_BUFFER, &msg);
        return msg.kernel_addr;
    }

    uint64_t AllocBuffer(const std::vector<uint8_t>& data, bool gfp_account) const {
        kpwn_message msg = { .length = data.size(), .data = (uint8_t*) data.data(), .gfp_account = gfp_account };
        Call(ALLOC_BUFFER, &msg);
        return msg.kernel_addr;
    }

    std::vector<uint8_t> Read(uint64_t ptr, uint64_t size) const {
        std::vector<uint8_t> result(size);
        std::memset(result.data(), 0, size);
        kpwn_message msg { .length = size, .data = result.data(), .kernel_addr = ptr };
        Call(ARB_READ, &msg);
        return result;
    }

    void Write(uint64_t ptr, const std::vector<uint8_t>& data) const {
        kpwn_message msg { .length = data.size(), .data = (uint8_t*) data.data(), .kernel_addr = ptr };
        Call(ARB_WRITE, &msg);
    }

    void Kfree(uint64_t ptr) const {
        Call(KFREE, (void*) ptr);
    }

    void Printk(const char* msg) const {
        Call(PRINTK, (void*) msg);
    }

    uint64_t KaslrLeak() {
        uint64_t kaslr_base;
        Call(KASLR_LEAK, &kaslr_base);
        return kaslr_base;
    }

    uint64_t WinTarget() {
        uint64_t win_target_addr;
        Call(WIN_TARGET, &win_target_addr);
        return win_target_addr;
    }

    std::optional<uint64_t> SymAddrOpt(const char* name) {
        sym_addr sym_addr;
        strncpy(sym_addr.symbol_name, name, sizeof(sym_addr.symbol_name));
        auto error = Call(SYM_ADDR, &sym_addr, ERROR_UNKNOWN_SYMBOL);
        return error == SUCCESS ? std::optional(sym_addr.symbol_addr) : std::nullopt;
    }

    uint64_t SymAddr(const char* name) {
        auto addr = SymAddrOpt(name);
        if (!addr.has_value())
            throw ExpKitError("symbol '%s' was not found in the kernel", name);
        return addr.value();
    }

    void RipControl(const rip_control_args& args) {
        Call(RIP_CONTROL, (void*) &args);
    }

    void RipControl(RipAction action, const std::map<Register, uint64_t>& regs = {}) {
        auto args = ConvertRipArgs(action, regs);
        RipControl(args);
    }

    void CallAddr(uint64_t addr, const std::map<Register, uint64_t>& regs = {}) {
        auto args = ConvertRipArgs(RipAction::Call, regs);
        args.rip = addr;
        RipControl(args);
    }

    void JumpToAddr(uint64_t addr, const std::map<Register, uint64_t>& regs = {}) {
        auto args = ConvertRipArgs(RipAction::Jmp, regs);
        args.rip = addr;
        RipControl(args);
    }

    void SetRspAndRet(uint64_t new_rsp, const std::map<Register, uint64_t>& regs = {}) {
        auto args = ConvertRipArgs(RipAction::Ret, regs);
        args.rsp = new_rsp;
        args.regs_to_set |= RSP;
        RipControl(args);
    }

    uint64_t GetRipControlRecoveryAddr() {
        uint64_t addr;
        Call(GET_RIP_CONTROL_RECOVERY, &addr);
        return addr;
    }

    Kprobe* InstallKprobe(const char* function_name, uint8_t arg_count = 0, enum kprobe_log_mode log_mode = (kprobe_log_mode)(ENTRY_WITH_CALLSTACK | RETURN), const char* log_call_stack_filter = nullptr) {
        auto* kprobe = new Kprobe(function_name, arg_count, log_mode, log_call_stack_filter);
        Call(INSTALL_KPROBE, &kprobe->args_);
        installed_probes_.insert(kprobe);
        if (kprobe->args_.installed_kprobe == nullptr)
            throw ExpKitError("Invalid installed kprobe pointer");
        return kprobe;
    }

    void RemoveKprobe(Kprobe* probe) {
        Call(REMOVE_KPROBE, probe->args_.installed_kprobe);
        installed_probes_.erase(probe);
        delete probe;
    }

    void PrintAllCallLog(bool clear_log = false) {
        for (auto probe: installed_probes_)
            probe->PrintCallLog(clear_log);
    }

    void CheckWin() {
        if (Syscalls::ioctl(fd_, CHECK_WIN, nullptr) != SUCCESS)
            throw ExpKitError("exploit failed, the win_target was not called :(");
    }

    void Close() {
        for (auto probe: std::set(installed_probes_))
            RemoveKprobe(probe);

        if (fd_ != -1) {
            Syscalls::close(fd_);
            fd_ = -1;
        }
    }

    ~Kpwn() {
        Close();
    }
};