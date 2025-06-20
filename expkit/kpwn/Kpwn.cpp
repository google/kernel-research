#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <set>
#include "./include/kpwn.h"
#include "util/error.hpp"
#include "util/syscalls.hpp"
#include "util/Register.hpp"
#include "Kpwn.hpp"

const char* kpwn_cmd_names[] = { "ALLOC_BUFFER", "KFREE", "KASLR_LEAK", "WIN_TARGET",
    "RIP_CONTROL", "ARB_READ", "ARB_WRITE", "INSTALL_KPROBE", "PRINTK", "SYM_ADDR",
    "REMOVE_KPROBE", "GET_RIP_CONTROL_RECOVERY", "CHECK_WIN" };

const char* kpwn_errors_names[] = {
    "ERROR_GENERIC",
    "ERROR_UNKNOWN_COMMAND",
    "ERROR_ALLOC",
    "ERROR_COPY_FROM_USER_STRUCT",
    "ERROR_COPY_FROM_USER_DATA",
    "ERROR_COPY_TO_USER_STRUCT",
    "ERROR_COPY_TO_USER_DATA",
    "ERROR_UNKNOWN_SYMBOL",
 };

std::string CallLog::GetSummary() {
  std::string probe_str;
  for (auto arg : arguments)
    probe_str += format_str("%s0x%lx", probe_str.size() == 0 ? "" : ", ", arg);
  return format_str("%s(%s) = 0x%lx", function_name, probe_str.c_str(),
                    return_value);
}

Kprobe::Kprobe(const char* function_name, uint8_t arg_count,
               enum kprobe_log_mode log_mode,
               const char* log_call_stack_filter) {
  args_ = {.pid_filter = getpid(),
           .arg_count = arg_count,
           .log_mode = (uint8_t)log_mode,
           .logs = 0};
  strcpy(args_.function_name, function_name);
  if (args_.log_mode & CALL_LOG) {
    if (log_call_stack_filter)
      strncpy(args_.log_call_stack_filter, log_call_stack_filter,
              sizeof(args_.log_call_stack_filter));

    kprobe_log* log = (kprobe_log*)mmap(NULL, logs_size, PROT_READ | PROT_WRITE,
                                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    log->struct_size = logs_size;
    log->missed_logs = 0;
    log->next_offset = 0;
    log->entry_count = 0;
    args_.logs = log;
  }
}

std::vector<CallLog> Kprobe::GetCallLogs(bool clear_log) {
  std::vector<CallLog> result;

  kprobe_log_entry* entry = args_.logs->entries;
  for (int i = 0; i < args_.logs->entry_count; i++) {
    CallLog log;
    log.function_name = args_.function_name;
    for (int j = 0; j < args_.arg_count; j++)
      log.arguments.push_back((uint64_t)entry->arguments[j]);
    log.return_value = entry->return_value;
    log.call_stack =
        std::string((char*)entry->call_stack, entry->call_stack_size);
    result.push_back(log);

    entry = (kprobe_log_entry*)(((uint8_t*)entry) + entry->entry_size);
  }

  if (clear_log) {
    args_.logs->entry_count = 0;
    args_.logs->next_offset = 0;
    args_.logs->missed_logs = 0;
  }

  return result;
}

void Kprobe::PrintCallLog(bool clear_log) {
  auto callLogs = GetCallLogs(clear_log);

  printf("%s call log (count = %lu):\n", args_.function_name, callLogs.size());

  int i = 0;
  for (auto callLog : callLogs)
    printf("  #%d: %s\n      call stack: %s\n", i++,
           callLog.GetSummary().c_str(), callLog.call_stack.c_str());
}

Kprobe::~Kprobe() {
  if (args_.logs) munmap(args_.logs, args_.logs->struct_size);
}

rip_control_args Kpwn::ConvertRipArgs(
    RipAction action, const std::map<Register, uint64_t>& regs) {
  rip_control_args args = {0};
  args.action = (uint64_t)action;

  for (const auto& regp : regs) {
    ((uint64_t*)&args)[(uint)regp.first] = regp.second;
    args.regs_to_set |= 1 << (uint)regp.first;
  }

  return args;
}

kpwn_error Kpwn::CallRaw(enum kpwn_cmd cmd, void* arg) const {
  kpwn_error error_code = (kpwn_error) - ::ioctl(fd_, cmd, arg);
  if (error_code == SUCCESS ||
      ERROR_GENERIC <= error_code && error_code <= ERROR_UNKNOWN_SYMBOL)
    return error_code;
  throw ExpKitError("kpwn command %s failed with unknown error code 0x%x");
}

bool Kpwn::IsAvailable() { return access(DEVICE_PATH, F_OK) != -1; }

Kpwn::Kpwn() { fd_ = Syscalls::open("/dev/kpwn", O_RDWR); }

kpwn_error Kpwn::Call(enum kpwn_cmd cmd, void* arg,
                      kpwn_error expected_error) const {
  auto error = CallRaw(cmd, arg);
  if (error != SUCCESS && error != expected_error)
    throw ExpKitError("kpwn command %s failed with error code 0x%x (%s)",
                      kpwn_cmd_names[cmd - 0x1000], error,
                      kpwn_errors_names[error - ERROR_GENERIC]);
  return error;
}

void Kpwn::Call(enum kpwn_cmd cmd, void* arg) const { Call(cmd, arg, SUCCESS); }

uint64_t Kpwn::AllocBuffer(uint64_t size, bool gfp_account) const {
  kpwn_message msg = {.length = size, .gfp_account = gfp_account};
  Call(ALLOC_BUFFER, &msg);
  return msg.kernel_addr;
}

uint64_t Kpwn::AllocBuffer(const std::vector<uint8_t>& data,
                           bool gfp_account) const {
  kpwn_message msg = {.length = data.size(),
                      .data = (uint8_t*)data.data(),
                      .gfp_account = gfp_account};
  Call(ALLOC_BUFFER, &msg);
  return msg.kernel_addr;
}

std::vector<uint8_t> Kpwn::Read(uint64_t ptr, uint64_t size) const {
  std::vector<uint8_t> result(size);
  std::memset(result.data(), 0, size);
  kpwn_message msg{.length = size, .data = result.data(), .kernel_addr = ptr};
  Call(ARB_READ, &msg);
  return result;
}

void Kpwn::Write(uint64_t ptr, const std::vector<uint8_t>& data) const {
  kpwn_message msg{
      .length = data.size(), .data = (uint8_t*)data.data(), .kernel_addr = ptr};
  Call(ARB_WRITE, &msg);
}

void Kpwn::Kfree(uint64_t ptr) const { Call(KFREE, (void*)ptr); }

void Kpwn::Printk(const char* msg) const { Call(PRINTK, (void*)msg); }

uint64_t Kpwn::KaslrLeak() {
  uint64_t kaslr_base;
  Call(KASLR_LEAK, &kaslr_base);
  return kaslr_base;
}

uint64_t Kpwn::WinTarget() {
  uint64_t win_target_addr;

  Call(WIN_TARGET, &win_target_addr);
  return win_target_addr;
}

std::optional<uint64_t> Kpwn::SymAddrOpt(const char* name) {
  sym_addr sym_addr;
  strncpy(sym_addr.symbol_name, name, sizeof(sym_addr.symbol_name));
  auto error = Call(SYM_ADDR, &sym_addr, ERROR_UNKNOWN_SYMBOL);
  return error == SUCCESS ? std::optional(sym_addr.symbol_addr) : std::nullopt;
}

uint64_t Kpwn::SymAddr(const char* name) {
  auto addr = SymAddrOpt(name);
  if (!addr.has_value())
    throw ExpKitError("symbol '%s' was not found in the kernel", name);
  return addr.value();
}

void Kpwn::RipControl(const rip_control_args& args) {
  Call(RIP_CONTROL, (void*)&args);
}

void Kpwn::RipControl(RipAction action,
                      const std::map<Register, uint64_t>& regs) {
  auto args = ConvertRipArgs(action, regs);
  RipControl(args);
}

void Kpwn::CallAddr(uint64_t addr, const std::map<Register, uint64_t>& regs) {
  auto args = ConvertRipArgs(RipAction::Call, regs);

  args.rip = addr;
  RipControl(args);
}

void Kpwn::JumpToAddr(uint64_t addr, const std::map<Register, uint64_t>& regs) {
  auto args = ConvertRipArgs(RipAction::Jmp, regs);
  args.rip = addr;
  RipControl(args);
}

void Kpwn::SetRspAndRet(uint64_t new_rsp,
                        const std::map<Register, uint64_t>& regs) {
  auto args = ConvertRipArgs(RipAction::Ret, regs);
  args.rsp = new_rsp;
  args.regs_to_set |= RSP;
  RipControl(args);
}

uint64_t Kpwn::GetRipControlRecoveryAddr() {
  uint64_t addr;
  Call(GET_RIP_CONTROL_RECOVERY, &addr);
  return addr;
}

Kprobe* Kpwn::InstallKprobe(const char* function_name, uint8_t arg_count,
                            enum kprobe_log_mode log_mode,
                            const char* log_call_stack_filter) {
  auto* kprobe =
      new Kprobe(function_name, arg_count, log_mode, log_call_stack_filter);
  Call(INSTALL_KPROBE, &kprobe->args_);
  installed_probes_.insert(kprobe);
  if (kprobe->args_.installed_kprobe == nullptr)
    throw ExpKitError("Invalid installed kprobe pointer");
  return kprobe;
}

void Kpwn::RemoveKprobe(Kprobe* probe) {
  Call(REMOVE_KPROBE, probe->args_.installed_kprobe);
  installed_probes_.erase(probe);
  delete probe;
}

void Kpwn::PrintAllCallLog(bool clear_log) {
  for (auto probe : installed_probes_) probe->PrintCallLog(clear_log);
}

void Kpwn::CheckWin() {
  if (Syscalls::ioctl(fd_, CHECK_WIN, nullptr) != SUCCESS)
    throw ExpKitError("exploit failed, the win_target was not called :(");
}

void Kpwn::Close() {
  for (auto probe : std::set(installed_probes_)) RemoveKprobe(probe);

  if (fd_ != -1) {
    Syscalls::close(fd_);
    fd_ = -1;
  }
}

Kpwn::~Kpwn() { Close(); }
