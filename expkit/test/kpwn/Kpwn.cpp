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

/**
 * @brief Enum representing the possible actions for RIP control.
 */
enum class RipAction { Jmp = 0x1, Call = 0x2, Ret = 0x3 };

/**
 * @brief Structure to hold information about a kernel function call log.
 */
struct CallLog {
    /** @brief The name of the function that was called. */
    std::string function_name;

    /** @brief A vector of arguments passed to the function. */
    std::vector<uint64_t> arguments;
    
    /** @brief The return value of the function. */
    uint64_t return_value;

    /** @brief The call stack at the time of the function call. */
    std::string call_stack;

    std::string GetSummary() {
        std::string probe_str;
        for (auto arg : arguments)
            probe_str += format_str("%s0x%lx", probe_str.size() == 0 ? "" : ", ", arg);
        return format_str("%s(%s) = 0x%lx", function_name, probe_str.c_str(), return_value);
    }
};

class Kpwn;

/**
 * @brief Class representing a Kprobe in the kernel.
 */
class Kprobe {
    kprobe_args args_;
    const size_t logs_size = 16 * 4096;
public:
    /**
     * @brief Constructor for the Kprobe class.
     * @param function_name The name of the function to probe.
     * @param arg_count The number of arguments to log (default is 0).
     * @param log_mode The logging mode (default is ENTRY_WITH_CALLSTACK | RETURN).
     * @param log_call_stack_filter An optional filter for the call stack (default is nullptr).
     */
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

    /**
     * @brief Retrieves the call logs for this Kprobe.
     * @param clear_log Whether to clear the log after retrieving (default is false).
     * @return A vector of CallLog structures.
     */
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

    /**
     * @brief Prints the call logs for this Kprobe to the console.
     * @param clear_log Whether to clear the log after printing (default is false).
     */
    void PrintCallLog(bool clear_log = false) {
        auto callLogs = GetCallLogs(clear_log);

        printf("%s call log (count = %lu):\n", args_.function_name, callLogs.size());

        int i = 0;
        for (auto callLog : callLogs)
            printf("  #%d: %s\n      call stack: %s\n",
                i++, callLog.GetSummary().c_str(), callLog.call_stack.c_str());
    }

    /**
     * @brief Destructor for the Kprobe class.
     */
    ~Kprobe() {
        if (args_.logs)
            munmap(args_.logs, args_.logs->struct_size);
    }

    friend class Kpwn;
};

/**
 * @brief Class representing the interface to the kpwn kernel module.
 */
class Kpwn {
    /** @brief File descriptor for the kpwn kernel module. */
    int fd_;

    /** @brief The default logging mode for Kprobes. */
    enum kprobe_log_mode default_log_mode_ = (kprobe_log_mode)(ENTRY_WITH_CALLSTACK | RETURN);

    /**
     * @brief A set of pointers to the Kprobe objects that have been successfully installed
     * in the kernel. This is used to keep track of probes that need to be removed
     * when the Kpwn object is closed or destroyed.
     */
    std::set<Kprobe*> installed_probes_;

    /**
     * @brief Converts the provided RIP action and register map into a `rip_control_args` structure.
     *        This structure is used to communicate with the kernel module for RIP control.
     * @param action The desired RIP action (Jump, Call, or Return).
     * @param regs A map of registers to set before performing the RIP action.
     * @return A `rip_control_args` structure populated with the provided action and registers.
     */
    rip_control_args ConvertRipArgs(RipAction action, const std::map<Register, uint64_t>& regs = {}) {
        rip_control_args args = { 0 };
        args.action = (uint64_t) action;

        for (const auto& regp : regs) {
            ((uint64_t*)&args)[(uint)regp.first] = regp.second;
            args.regs_to_set |= 1 << (uint)regp.first;
        }

        return args;
    }

    /**
     * @brief Calls a raw ioctl command on the kpwn device.
     * @param cmd The command to call.
     * @param arg The argument to the command.
     * @return The error code returned by the ioctl.
     * @throws ExpKitError if the ioctl returns an unknown error code.
     */
    kpwn_error CallRaw(enum kpwn_cmd cmd, void* arg) const {
        kpwn_error error_code = (kpwn_error) -::ioctl(fd_, cmd, arg);
        if (error_code == SUCCESS || ERROR_GENERIC <= error_code && error_code <= ERROR_UNKNOWN_SYMBOL) return error_code;
        throw ExpKitError("kpwn command %s failed with unknown error code 0x%x");
    }

public:
    /**
     * @brief Checks if the kpwn device is available.
     * @return True if the device exists, false otherwise.
     */
    static bool IsAvailable() {
        return access(DEVICE_PATH, F_OK) != -1;
    }

    /**
 * @brief Constructor for the Kpwn class.
 * @throws ExpKitError if the kpwn device cannot be opened.
 */
    Kpwn() {
        fd_ = Syscalls::open("/dev/kpwn", O_RDWR);
    }

    /**
     * @brief Calls a kpwn command and checks the error code.
     * @param cmd The command to call.
     * @param arg The argument to the command.
     * @param expected_error The expected error code if the command is not successful.
     * @throws ExpKitError if the command was not successful and did not return with expected_error.
     */
    kpwn_error Call(enum kpwn_cmd cmd, void* arg, kpwn_error expected_error) const {
        auto error = CallRaw(cmd, arg);
        if (error != SUCCESS && error != expected_error)
            throw ExpKitError("kpwn command %s failed with error code 0x%x (%s)", kpwn_cmd_names[cmd - 0x1000], error,
                kpwn_errors_names[error - ERROR_GENERIC]);
        return error;
    }

    /**
     * @brief Calls a kpwn command expecting success.
     * @param cmd The command to call.
     * @param arg The argument to the command.
     * @throws ExpKitError if the command was not successful.
     */
    void Call(enum kpwn_cmd cmd, void* arg) const {
        Call(cmd, arg, SUCCESS);
    }

    /**
     * @brief Allocates a buffer in kernel space.
     * @param size The size of the buffer to allocate.
     * @param gfp_account Whether to account for GFP_KERNEL allocations.
     * @return The kernel address of the allocated buffer.
     */
    uint64_t AllocBuffer(uint64_t size, bool gfp_account) const {
        kpwn_message msg = { .length = size, .gfp_account = gfp_account };
        Call(ALLOC_BUFFER, &msg);
        return msg.kernel_addr;
    }

    /**
     * @brief Allocates a buffer in kernel space and copies data into it.
     * @param data The data to copy into the buffer.
     * @param gfp_account Whether to account for GFP_KERNEL allocations.
     * @return The kernel address of the allocated buffer.
     */
    uint64_t AllocBuffer(const std::vector<uint8_t>& data, bool gfp_account) const {
        kpwn_message msg = { .length = data.size(), .data = (uint8_t*) data.data(), .gfp_account = gfp_account };
        Call(ALLOC_BUFFER, &msg);
        return msg.kernel_addr;
    }

    /**
     * @brief Reads data from kernel space.
     * @param ptr The kernel address to read from.
     * @param size The number of bytes to read.
     */
    std::vector<uint8_t> Read(uint64_t ptr, uint64_t size) const {
        std::vector<uint8_t> result(size);
        std::memset(result.data(), 0, size);
        kpwn_message msg { .length = size, .data = result.data(), .kernel_addr = ptr };
        Call(ARB_READ, &msg);
        return result;
    }

    /**
     * @brief Writes data to kernel space.
     * @param ptr The kernel address to write to.
     * @param data The data to write.
     */
    void Write(uint64_t ptr, const std::vector<uint8_t>& data) const {
        kpwn_message msg { .length = data.size(), .data = (uint8_t*) data.data(), .kernel_addr = ptr };
        Call(ARB_WRITE, &msg);
    }

    /**
     * @brief Frees a kernel buffer.
     * @param ptr The kernel address of the buffer to free.
     */
    void Kfree(uint64_t ptr) const {
        Call(KFREE, (void*) ptr);
    }

    /**
     * @brief Prints a message to the kernel log.
     * @param msg The message to print.
     */
    void Printk(const char* msg) const {
        Call(PRINTK, (void*) msg);
    }

    /**
     * @brief Gets the KASLR base address.
     * @return The KASLR base address.
     */
    uint64_t KaslrLeak() {
        uint64_t kaslr_base;
        Call(KASLR_LEAK, &kaslr_base);
        return kaslr_base;
    }

    /**
     * @brief Gets the address of the win target function.
     * @return The address of the win target function.
     * @details If the win target is called (e.g. via ROP chain), then it sets a win flag in the kernel which can be checked with the CheckWin() function.
     */
    uint64_t WinTarget() {
        uint64_t win_target_addr;

        Call(WIN_TARGET, &win_target_addr);
        return win_target_addr;
    }

    /**
     * @brief Gets the address of a kernel symbol if it exists in kallsyms.
     * @param name The name of the symbol.
     * @return An optional containing the address of the symbol if found, otherwise an empty optional.
     */
    std::optional<uint64_t> SymAddrOpt(const char* name) {
        sym_addr sym_addr;
        strncpy(sym_addr.symbol_name, name, sizeof(sym_addr.symbol_name));
        auto error = Call(SYM_ADDR, &sym_addr, ERROR_UNKNOWN_SYMBOL);
        return error == SUCCESS ? std::optional(sym_addr.symbol_addr) : std::nullopt;
    }

    /**
     * @brief Gets the address of a kernel symbol if it exists in kallsyms.
     * @param name The name of the symbol.
     * @throws ExpKitError if the symbol was not found in kallsyms.
     * @return The address of the symbol.
     */
    uint64_t SymAddr(const char* name) {
        auto addr = SymAddrOpt(name);
        if (!addr.has_value())
            throw ExpKitError("symbol '%s' was not found in the kernel", name);
        return addr.value();
    }

    /**
     * @brief Controls the RIP and other registers in the kernel.
     * @param args The arguments for controlling the RIP and registers.
     */
    void RipControl(const rip_control_args& args) {
        Call(RIP_CONTROL, (void*) &args);
    }

    /**
     * @brief Controls the RIP and other registers in the kernel.
     * @param action The action to perform (Jump, Call, or Return).
     * @param regs A map of registers to set and their values.
     */
    void RipControl(RipAction action, const std::map<Register, uint64_t>& regs = {}) {
        auto args = ConvertRipArgs(action, regs);
        RipControl(args);
    }

    /**
     * @brief Calls a kernel function at a specific address (with the "call" asm call).
     * @param addr The address of the function to call.
     * @param regs A map of registers to set before the call.
     */
    void CallAddr(uint64_t addr, const std::map<Register, uint64_t>& regs = {}) {

        auto args = ConvertRipArgs(RipAction::Call, regs);

        args.rip = addr;
        RipControl(args);
    }

    /**
     * @brief Jumps to a specific address in the kernel (with the "jmp" asm call).
     * @param addr The address to jump to.
     * @param regs A map of registers to set before the jump.
     */
    void JumpToAddr(uint64_t addr, const std::map<Register, uint64_t>& regs = {}) {
        auto args = ConvertRipArgs(RipAction::Jmp, regs);
        args.rip = addr;
        RipControl(args);
    }

    /**
     * @brief Sets the RSP and performs a return ("mov rsp, <new_rsp>; ret").
     * @param new_rsp The new value for the RSP.
     * @param regs A map of registers to set before the return.
     */
    void SetRspAndRet(uint64_t new_rsp, const std::map<Register, uint64_t>& regs = {}) {
        auto args = ConvertRipArgs(RipAction::Ret, regs);
        args.rsp = new_rsp;
        args.regs_to_set |= RSP;
        RipControl(args);
    }

    /**
     * @brief Gets the recovery address for RIP control.
     * @return The recovery address.
     */
    uint64_t GetRipControlRecoveryAddr() {
        uint64_t addr;
        Call(GET_RIP_CONTROL_RECOVERY, &addr);
        return addr;
    }

    /**
     * @brief Installs a Kprobe in the kernel.
     * @param function_name The name of the function to probe.
     * @param arg_count The number of arguments to log (default is 0).
     * @param log_mode The logging mode (default is ENTRY_WITH_CALLSTACK | RETURN).
     * @param log_call_stack_filter An optional filter for the call stack (default is nullptr which means no call stack filtering, all calls are recorded).
     * @return A pointer to the installed Kprobe object.
     */
    Kprobe* InstallKprobe(const char* function_name, uint8_t arg_count = 0, enum kprobe_log_mode log_mode = (kprobe_log_mode)(ENTRY_WITH_CALLSTACK | RETURN), const char* log_call_stack_filter = nullptr) {
        auto* kprobe = new Kprobe(function_name, arg_count, log_mode, log_call_stack_filter);
        Call(INSTALL_KPROBE, &kprobe->args_);
        installed_probes_.insert(kprobe);
        if (kprobe->args_.installed_kprobe == nullptr)
            throw ExpKitError("Invalid installed kprobe pointer");
        return kprobe;
    }

    /**
     * @brief Removes an installed Kprobe.
     * @param probe A pointer to the Kprobe object to remove.
     */
    void RemoveKprobe(Kprobe* probe) {
        Call(REMOVE_KPROBE, probe->args_.installed_kprobe);
        installed_probes_.erase(probe);
        delete probe;
    }

    /**
     * @brief Prints the call logs for all installed Kprobes.
     * @param clear_log Whether to clear the logs after printing (default is false).
     */
    void PrintAllCallLog(bool clear_log = false) {
        for (auto probe: installed_probes_)
            probe->PrintCallLog(clear_log);
    }
    /**
     * @brief Checks if the win target has been called.
     */
    void CheckWin() {
        if (Syscalls::ioctl(fd_, CHECK_WIN, nullptr) != SUCCESS)
            throw ExpKitError("exploit failed, the win_target was not called :(");
    }

    /**
     * @brief Closes the connection to the kpwn device and removes all installed Kprobes.
     */
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