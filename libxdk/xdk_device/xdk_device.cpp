// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <xdk/xdk_device/xdk_device.h>
#include <xdk/util/error.h>
#include <xdk/util/syscalls.h>
#include <xdk/util/Register.h>

#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <set>

const char* xdk_cmd_names[] = { "ALLOC_BUFFER", "KFREE", "KASLR_LEAK", "WIN_TARGET",
    "RIP_CONTROL", "ARB_READ", "ARB_WRITE", "INSTALL_KPROBE", "PRINTK", "SYM_ADDR",
    "REMOVE_KPROBE", "GET_RIP_CONTROL_RECOVERY", "CHECK_WIN" };

const char* xdk_errors_names[] = {
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

rip_control_args XdkDevice::ConvertRipArgs(
    RipAction action, const std::map<Register, uint64_t>& regs) {
  rip_control_args args = {0};
  args.action = (uint64_t)action;

  for (const auto& regp : regs) {
    ((uint64_t*)&args)[(uint)regp.first] = regp.second;
    args.regs_to_set |= 1 << (uint)regp.first;
  }

  return args;
}

xdk_error XdkDevice::CallRaw(enum xdk_cmd cmd, void* arg) const {
  xdk_error error_code = (xdk_error) - ::ioctl(fd_, cmd, arg);
  if (error_code == SUCCESS ||
      ERROR_GENERIC <= error_code && error_code <= ERROR_UNKNOWN_SYMBOL)
    return error_code;
  throw ExpKitError("xdk command %s failed with unknown error code 0x%x");
}

bool XdkDevice::IsAvailable() { return access(DEVICE_PATH, F_OK) != -1; }

XdkDevice::XdkDevice() { fd_ = Syscalls::open("/dev/xdk", O_RDWR); }

xdk_error XdkDevice::Call(enum xdk_cmd cmd, void* arg,
                      xdk_error expected_error) const {
  auto error = CallRaw(cmd, arg);
  if (error != SUCCESS && error != expected_error)
    throw ExpKitError("xdk command %s failed with error code 0x%x (%s)",
                      xdk_cmd_names[cmd - 0x1000], error,
                      xdk_errors_names[error - ERROR_GENERIC]);
  return error;
}

void XdkDevice::Call(enum xdk_cmd cmd, void* arg) const { Call(cmd, arg, SUCCESS); }

uint64_t XdkDevice::AllocBuffer(uint64_t size, bool gfp_account) const {
  xdk_message msg = {.length = size, .gfp_account = gfp_account};
  Call(ALLOC_BUFFER, &msg);
  return msg.kernel_addr;
}

uint64_t XdkDevice::AllocBuffer(const std::vector<uint8_t>& data,
                           bool gfp_account) const {
  xdk_message msg = {.length = data.size(),
                      .data = (uint8_t*)data.data(),
                      .gfp_account = gfp_account};
  Call(ALLOC_BUFFER, &msg);
  return msg.kernel_addr;
}

std::vector<uint8_t> XdkDevice::Read(uint64_t ptr, uint64_t size) const {
  std::vector<uint8_t> result(size);
  std::memset(result.data(), 0, size);
  xdk_message msg{.length = size, .data = result.data(), .kernel_addr = ptr};
  Call(ARB_READ, &msg);
  return result;
}

void XdkDevice::Write(uint64_t ptr, const std::vector<uint8_t>& data) const {
  xdk_message msg{
      .length = data.size(), .data = (uint8_t*)data.data(), .kernel_addr = ptr};
  Call(ARB_WRITE, &msg);
}

void XdkDevice::Kfree(uint64_t ptr) const { Call(KFREE, (void*)ptr); }

void XdkDevice::Printk(const char* msg) const { Call(PRINTK, (void*)msg); }

uint64_t XdkDevice::KaslrLeak() {
  uint64_t kaslr_base;
  Call(KASLR_LEAK, &kaslr_base);
  return kaslr_base;
}

uint64_t XdkDevice::WinTarget() {
  uint64_t win_target_addr;

  Call(WIN_TARGET, &win_target_addr);
  return win_target_addr;
}

std::optional<uint64_t> XdkDevice::SymAddrOpt(const char* name) {
  sym_addr sym_addr;
  strncpy(sym_addr.symbol_name, name, sizeof(sym_addr.symbol_name));
  auto error = Call(SYM_ADDR, &sym_addr, ERROR_UNKNOWN_SYMBOL);
  return error == SUCCESS ? std::optional(sym_addr.symbol_addr) : std::nullopt;
}

uint64_t XdkDevice::SymAddr(const char* name) {
  auto addr = SymAddrOpt(name);
  if (!addr.has_value())
    throw ExpKitError("symbol '%s' was not found in the kernel", name);
  return addr.value();
}

void XdkDevice::RipControl(const rip_control_args& args) {
  Call(RIP_CONTROL, (void*)&args);
}

void XdkDevice::RipControl(RipAction action,
                      const std::map<Register, uint64_t>& regs) {
  auto args = ConvertRipArgs(action, regs);
  RipControl(args);
}

void XdkDevice::CallAddr(uint64_t addr, const std::map<Register, uint64_t>& regs) {
  auto args = ConvertRipArgs(RipAction::Call, regs);

  args.rip = addr;
  RipControl(args);
}

void XdkDevice::JumpToAddr(uint64_t addr, const std::map<Register, uint64_t>& regs) {
  auto args = ConvertRipArgs(RipAction::Jmp, regs);
  args.rip = addr;
  RipControl(args);
}

void XdkDevice::SetRspAndRet(uint64_t new_rsp,
                        const std::map<Register, uint64_t>& regs) {
  auto args = ConvertRipArgs(RipAction::Ret, regs);
  args.rsp = new_rsp;
  args.regs_to_set |= RSP;
  RipControl(args);
}

uint64_t XdkDevice::GetRipControlRecoveryAddr() {
  uint64_t addr;
  Call(GET_RIP_CONTROL_RECOVERY, &addr);
  return addr;
}

Kprobe* XdkDevice::InstallKprobe(const char* function_name, uint8_t arg_count,
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

void XdkDevice::RemoveKprobe(Kprobe* probe) {
  Call(REMOVE_KPROBE, probe->args_.installed_kprobe);
  installed_probes_.erase(probe);
  delete probe;
}

void XdkDevice::PrintAllCallLog(bool clear_log) {
  for (auto probe : installed_probes_) probe->PrintCallLog(clear_log);
}

void XdkDevice::CheckWin() {
  if (Syscalls::ioctl(fd_, CHECK_WIN, nullptr) != SUCCESS)
    throw ExpKitError("exploit failed, the win_target was not called :(");
}

void XdkDevice::Close() {
  for (auto probe : std::set(installed_probes_)) RemoveKprobe(probe);

  if (fd_ != -1) {
    Syscalls::close(fd_);
    fd_ = -1;
  }
}

XdkDevice::~XdkDevice() { Close(); }
