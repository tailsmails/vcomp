module vcomp

#flag -D_GNU_SOURCE
#include <sys/prctl.h>
#include <linux/filter.h>

pub const bpf_ld = u16(0x00)
pub const bpf_w = u16(0x00)
pub const bpf_abs = u16(0x20)
pub const bpf_jmp = u16(0x05)
pub const bpf_jeq = u16(0x15)
pub const bpf_k = u16(0x00)
pub const bpf_ret = u16(0x06)

pub const seccomp_ret_kill_process = u32(0x80000000)
pub const seccomp_ret_kill_thread = u32(0x00000000)
pub const seccomp_ret_trap = u32(0x00030000)
pub const seccomp_ret_errno = u32(0x00050000)
pub const seccomp_ret_allow = u32(0x7fff0000)

pub const audit_arch_x86_64 = u32(0xc000003e)
pub const audit_arch_i386 = u32(0x40000003)
pub const audit_arch_aarch64 = u32(0xc00000b7)
pub const audit_arch_arm = u32(0x40000028)
pub const audit_arch_riscv64 = u32(0xc00000f3)

pub struct C.sock_filter {
pub mut:
	code u16
	jt   u8
	jf   u8
	k    u32
}

pub struct C.sock_fprog {
pub mut:
	len    u16
	filter &C.sock_filter
}

fn C.prctl(option int, arg2 u64, arg3 u64, arg4 u64, arg5 u64) int

pub enum FilterType {
	blocklist
	allowlist
}

pub enum Action {
	kill_process
	kill_thread
	trap
	allow
	errno_error
}

pub type Syscall = int | string

pub struct FilterConfig {
pub:
	filter_type FilterType = .blocklist
	syscalls    []Syscall
	action      Action = .kill_process
	errno_code  int    = 1
}

fn get_audit_arch() u32 {
	$if amd64 {
		return audit_arch_x86_64
	} $else $if arm64 {
		return audit_arch_aarch64
	} $else $if i386 {
		return audit_arch_i386
	} $else $if arm32 {
		return audit_arch_arm
	} $else $if rv64 {
		return audit_arch_riscv64
	} $else {
		return 0
	}
}

fn get_action_value(action Action, errno_code int) u32 {
	match action {
		.kill_process { return seccomp_ret_kill_process }
		.kill_thread  { return seccomp_ret_kill_thread }
		.trap         { return seccomp_ret_trap }
		.allow        { return seccomp_ret_allow }
		.errno_error  { return seccomp_ret_errno | u32(errno_code & 0xffff) }
	}
}

fn resolve_syscall(sys Syscall) !int {
	match sys {
		int {
			return sys
		}
		string {
			$if amd64 {
				match sys {
					'read' { return 0 }
					'write' { return 1 }
					'open' { return 2 }
					'close' { return 3 }
					'ptrace' { return 101 }
					'reboot' { return 169 }
					'clone' { return 56 }
					'fork' { return 57 }
					'vfork' { return 58 }
					'execve' { return 59 }
					'execveat' { return 322 }
					'openat' { return 257 }
					'socket' { return 41 }
					'connect' { return 42 }
					'accept' { return 43 }
					'listen' { return 50 }
					'bind' { return 49 }
					'kill' { return 62 }
					'tkill' { return 200 }
					'tgkill' { return 234 }
					else { return error('syscall "${sys}" is not supported on this architecture') }
				}
			} $else $if arm64 {
				match sys {
					'read' { return 63 }
					'write' { return 64 }
					'close' { return 57 }
					'ptrace' { return 117 }
					'reboot' { return 142 }
					'clone' { return 220 }
					'execve' { return 221 }
					'execveat' { return 281 }
					'openat' { return 56 }
					'socket' { return 198 }
					'connect' { return 203 }
					'accept' { return 202 }
					'listen' { return 201 }
					'bind' { return 200 }
					'kill' { return 129 }
					'tkill' { return 130 }
					'tgkill' { return 131 }
					else { return error('syscall "${sys}" is not supported on this architecture') }
				}
			} $else $if i386 {
				match sys {
					'read' { return 3 }
					'write' { return 4 }
					'open' { return 5 }
					'close' { return 6 }
					'ptrace' { return 26 }
					'reboot' { return 88 }
					'clone' { return 120 }
					'fork' { return 2 }
					'vfork' { return 190 }
					'execve' { return 11 }
					'execveat' { return 358 }
					'openat' { return 295 }
					'socket' { return 359 }
					'connect' { return 362 }
					'accept' { return 364 }
					'listen' { return 363 }
					'bind' { return 361 }
					'kill' { return 37 }
					'tkill' { return 238 }
					'tgkill' { return 270 }
					else { return error('syscall "${sys}" is not supported on this architecture') }
				}
			} $else $if arm32 {
				match sys {
					'read' { return 3 }
					'write' { return 4 }
					'open' { return 5 }
					'close' { return 6 }
					'ptrace' { return 26 }
					'reboot' { return 88 }
					'clone' { return 120 }
					'fork' { return 2 }
					'vfork' { return 190 }
					'execve' { return 11 }
					'execveat' { return 343 }
					'openat' { return 322 }
					'socket' { return 281 }
					'connect' { return 283 }
					'accept' { return 285 }
					'listen' { return 284 }
					'bind' { return 282 }
					'kill' { return 37 }
					'tkill' { return 238 }
					'tgkill' { return 268 }
					else { return error('syscall "${sys}" is not supported on this architecture') }
				}
			} $else $if rv64 {
				match sys {
					'read' { return 63 }
					'write' { return 64 }
					'close' { return 57 }
					'ptrace' { return 117 }
					'reboot' { return 142 }
					'clone' { return 220 }
					'execve' { return 221 }
					'execveat' { return 281 }
					'openat' { return 56 }
					'socket' { return 198 }
					'connect' { return 203 }
					'accept' { return 202 }
					'listen' { return 201 }
					'bind' { return 200 }
					'kill' { return 129 }
					'tkill' { return 130 }
					'tgkill' { return 131 }
					else { return error('syscall "${sys}" is not supported on this architecture') }
				}
			} $else {
				return error('architecture not supported for string syscall lookup')
			}
		}
	}
}

pub fn get_syscall_number(sys Syscall) !int {
	return resolve_syscall(sys)!
}

pub fn build_bpf_filter(config FilterConfig) ![]C.sock_filter {
	if config.syscalls.len == 0 {
		return error('syscall list cannot be empty')
	}

	target_arch := get_audit_arch()
	if target_arch == 0 {
		return error('unsupported CPU architecture for BPF filtering')
	}

	mut resolved_syscalls := []int{cap: config.syscalls.len}
	for sys in config.syscalls {
		resolved_syscalls << resolve_syscall(sys)!
	}

	mut filter := []C.sock_filter{cap: resolved_syscalls.len + 6}

	filter << C.sock_filter{
		code: bpf_ld | bpf_w | bpf_abs
		jt: 0
		jf: 0
		k: 4
	}
	filter << C.sock_filter{
		code: bpf_jmp | bpf_jeq | bpf_k
		jt: 1
		jf: 0
		k: target_arch
	}
	filter << C.sock_filter{
		code: bpf_ret | bpf_k
		jt: 0
		jf: 0
		k: seccomp_ret_kill_process
	}

	filter << C.sock_filter{
		code: bpf_ld | bpf_w | bpf_abs
		jt: 0
		jf: 0
		k: 0
	}

	n := resolved_syscalls.len
	for i, sys_nr in resolved_syscalls {
		jt_offset := u8(n - i)
		filter << C.sock_filter{
			code: bpf_jmp | bpf_jeq | bpf_k
			jt:   jt_offset
			jf:   0
			k:    u32(sys_nr)
		}
	}

	matched_action_val := get_action_value(config.action, config.errno_code)
	default_action_val := seccomp_ret_allow

	mut default_action := default_action_val
	mut matched_action := matched_action_val

	if config.filter_type == .allowlist {
		default_action = matched_action_val
		matched_action = default_action_val
	}

	filter << C.sock_filter{
		code: bpf_ret | bpf_k
		jt: 0
		jf: 0
		k: default_action
	}
	filter << C.sock_filter{
		code: bpf_ret | bpf_k
		jt: 0
		jf: 0
		k: matched_action
	}

	return filter
}

pub fn apply(config FilterConfig) ! {
	$if linux || android || termux {
		if unsafe { C.prctl(38, 1, 0, 0, 0) } == -1 {
			return error('failed to set no_new_privs')
		}

		filter_bytecode := build_bpf_filter(config)!

		prog := C.sock_fprog{
			len:    u16(filter_bytecode.len)
			filter: &filter_bytecode[0]
		}

		if unsafe { C.prctl(22, 2, u64(voidptr(&prog)), 0, 0) } == -1 {
			return error('failed to load raw bpf filter')
		}
	} $else {
		return error('bpf filtering is only supported on linux, android, and termux')
	}
}

pub fn block(syscalls []Syscall) ! {
	apply(
		filter_type: .blocklist
		syscalls: syscalls
		action: .kill_process
	)!
}

pub fn block_with_errno(syscalls []Syscall, errno_code int) ! {
	apply(
		filter_type: .blocklist
		syscalls: syscalls
		action: .errno_error
		errno_code: errno_code
	)!
}

pub fn allow(syscalls []Syscall) ! {
	apply(
		filter_type: .allowlist
		syscalls: syscalls
		action: .kill_process
	)!
}