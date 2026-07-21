module vcomp

import os

#flag -D_GNU_SOURCE

$if linux || android || termux {
	#include <sys/prctl.h>
	#include <linux/filter.h>

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
	fn C.syscall(number int, arg1 voidptr, arg2 voidptr, arg3 voidptr, arg4 voidptr, arg5 voidptr, arg6 voidptr) i64
} $else {
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
}

pub const pr_set_no_new_privs = 38
pub const pr_set_seccomp = 22
pub const seccomp_mode_filter = 2

pub const bpf_ld = u16(0x00)
pub const bpf_w = u16(0x00)
pub const bpf_abs = u16(0x20)
pub const bpf_jmp = u16(0x05)
pub const bpf_jeq = u16(0x15)
pub const bpf_jgt = u16(0x25)
pub const bpf_jge = u16(0x35)
pub const bpf_jset = u16(0x45)
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

pub enum Op {
	eq
	neq
	gt
	ge
	bits_set
}

pub struct ArgRule {
pub:
	index int
	op    Op = .eq
	value u64
}

pub type Syscall = int | string
pub type SyscallArg = int | u64 | voidptr | string

pub struct SyscallRule {
pub:
	sys    Syscall
	action Action = .kill_process
pub mut:
	args   []ArgRule
}

pub struct FilterConfig {
pub:
	filter_type FilterType = .blocklist
	rules       []SyscallRule
	errno_code  int        = 1
}

pub struct FilterBuilder {
pub mut:
	filter_type FilterType = .blocklist
	rules       []SyscallRule
	errno_code  int        = 1
}

pub fn new_filter() FilterBuilder {
	return FilterBuilder{}
}

pub fn (b FilterBuilder) set_type(t FilterType) FilterBuilder {
	mut new_b := b
	new_b.rules = b.rules.clone()
	new_b.filter_type = t
	return new_b
}

pub fn (b FilterBuilder) set_errno(code int) FilterBuilder {
	mut new_b := b
	new_b.rules = b.rules.clone()
	new_b.errno_code = code
	return new_b
}

pub fn (b FilterBuilder) block(sys Syscall) FilterBuilder {
	mut new_b := b
	new_b.rules = b.rules.clone()
	new_b.rules << SyscallRule{
		sys: sys
		action: .kill_process
	}
	return new_b
}

pub fn (b FilterBuilder) block_with_errno(sys Syscall) FilterBuilder {
	mut new_b := b
	new_b.rules = b.rules.clone()
	new_b.rules << SyscallRule{
		sys: sys
		action: .errno_error
	}
	return new_b
}

pub fn (b FilterBuilder) allow(sys Syscall) FilterBuilder {
	mut new_b := b
	new_b.rules = b.rules.clone()
	new_b.rules << SyscallRule{
		sys: sys
		action: .allow
	}
	return new_b
}

pub fn (b FilterBuilder) where_arg(index int, op Op, value u64) FilterBuilder {
	mut new_b := b
	new_b.rules = b.rules.clone()
	if new_b.rules.len > 0 {
		last_idx := new_b.rules.len - 1
		mut rule := new_b.rules[last_idx]
		rule.args = rule.args.clone()
		rule.args << ArgRule{
			index: index
			op: op
			value: value
		}
		unsafe {
			new_b.rules[last_idx] = rule
		}
	}
	return new_b
}

pub fn (b FilterBuilder) apply() ! {
	apply(
		filter_type: b.filter_type
		rules: b.rules
		errno_code: b.errno_code
	)!
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

fn cast_arg(arg SyscallArg) voidptr {
	match arg {
		int { return voidptr(usize(arg)) }
		u64 { return voidptr(usize(arg)) }
		voidptr { return arg }
		string { return voidptr(arg.str) }
	}
}

pub fn call(sys Syscall, args ...SyscallArg) !i64 {
	$if linux || android || termux {
		sys_nr := resolve_syscall(sys)!
		mut c_args := []voidptr{len: 6, init: voidptr(0)}
		for i, arg in args {
			if i >= 6 {
				break
			}
			c_args[i] = cast_arg(arg)
		}
		res := unsafe { C.syscall(sys_nr, c_args[0], c_args[1], c_args[2], c_args[3], c_args[4], c_args[5]) }
		if res == -1 {
			return error(os.error_posix().msg())
		}
		return res
	} $else {
		return error('syscall execution is only supported on linux, android, and termux')
	}
}

pub fn get_syscall_number(sys Syscall) !int {
	return resolve_syscall(sys)!
}

pub fn build_bpf_filter(config FilterConfig) ![]C.sock_filter {
	if config.rules.len == 0 {
		return error('rules list cannot be empty')
	}

	target_arch := get_audit_arch()
	if target_arch == 0 {
		return error('unsupported CPU architecture for BPF filtering')
	}

	mut filter := []C.sock_filter{cap: config.rules.len * 5 + 6}

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

	default_action_val := if config.filter_type == .allowlist {
		seccomp_ret_kill_process
	} else {
		seccomp_ret_allow
	}

	for rule in config.rules {
		sys_nr := resolve_syscall(rule.sys)!
		matched_action_val := get_action_value(rule.action, config.errno_code)

		mut rule_filter := []C.sock_filter{}

		for k, arg_rule in rule.args {
			val_lo := u32(arg_rule.value & 0xffffffff)
			val_hi := u32(arg_rule.value >> 32)
			arg_offset := u32(16 + arg_rule.index * 8)

			mut r := 0
			for m in (k + 1) .. rule.args.len {
				if rule.args[m].op == .gt || rule.args[m].op == .ge {
					r += 5
				} else {
					r += 4
				}
			}

			r_fail := u8(r + 1)

			match arg_rule.op {
				.eq {
					rule_filter << C.sock_filter{ code: bpf_ld | bpf_w | bpf_abs, k: arg_offset }
					rule_filter << C.sock_filter{ code: bpf_jmp | bpf_jeq | bpf_k, jt: 0, jf: u8(r + 3), k: val_lo }
					rule_filter << C.sock_filter{ code: bpf_ld | bpf_w | bpf_abs, k: arg_offset + 4 }
					rule_filter << C.sock_filter{ code: bpf_jmp | bpf_jeq | bpf_k, jt: 0, jf: r_fail, k: val_hi }
				}
				.neq {
					rule_filter << C.sock_filter{ code: bpf_ld | bpf_w | bpf_abs, k: arg_offset }
					rule_filter << C.sock_filter{ code: bpf_jmp | bpf_jeq | bpf_k, jt: 0, jf: 2, k: val_lo }
					rule_filter << C.sock_filter{ code: bpf_ld | bpf_w | bpf_abs, k: arg_offset + 4 }
					rule_filter << C.sock_filter{ code: bpf_jmp | bpf_jeq | bpf_k, jt: r_fail, jf: 0, k: val_hi }
				}
				.bits_set {
					rule_filter << C.sock_filter{ code: bpf_ld | bpf_w | bpf_abs, k: arg_offset }
					rule_filter << C.sock_filter{ code: bpf_jmp | bpf_jset | bpf_k, jt: 2, jf: 0, k: val_lo }
					rule_filter << C.sock_filter{ code: bpf_ld | bpf_w | bpf_abs, k: arg_offset + 4 }
					rule_filter << C.sock_filter{ code: bpf_jmp | bpf_jset | bpf_k, jt: 0, jf: r_fail, k: val_hi }
				}
				.gt {
					rule_filter << C.sock_filter{ code: bpf_ld | bpf_w | bpf_abs, k: arg_offset + 4 }
					rule_filter << C.sock_filter{ code: bpf_jmp | bpf_jgt | bpf_k, jt: 3, jf: 0, k: val_hi }
					rule_filter << C.sock_filter{ code: bpf_jmp | bpf_jeq | bpf_k, jt: 0, jf: u8(r + 3), k: val_hi }
					rule_filter << C.sock_filter{ code: bpf_ld | bpf_w | bpf_abs, k: arg_offset }
					rule_filter << C.sock_filter{ code: bpf_jmp | bpf_jgt | bpf_k, jt: 0, jf: r_fail, k: val_lo }
				}
				.ge {
					rule_filter << C.sock_filter{ code: bpf_ld | bpf_w | bpf_abs, k: arg_offset + 4 }
					rule_filter << C.sock_filter{ code: bpf_jmp | bpf_jgt | bpf_k, jt: 3, jf: 0, k: val_hi }
					rule_filter << C.sock_filter{ code: bpf_jmp | bpf_jeq | bpf_k, jt: 0, jf: u8(r + 3), k: val_hi }
					rule_filter << C.sock_filter{ code: bpf_ld | bpf_w | bpf_abs, k: arg_offset }
					rule_filter << C.sock_filter{ code: bpf_jmp | bpf_jge | bpf_k, jt: 0, jf: r_fail, k: val_lo }
				}
			}
		}

		skip_offset := u8(rule_filter.len + 1)
		filter << C.sock_filter{
			code: bpf_jmp | bpf_jeq | bpf_k
			jt: 0
			jf: skip_offset
			k: u32(sys_nr)
		}

		for f in rule_filter {
			filter << f
		}

		filter << C.sock_filter{
			code: bpf_ret | bpf_k
			jt: 0
			jf: 0
			k: matched_action_val
		}
	}

	filter << C.sock_filter{
		code: bpf_ret | bpf_k
		jt: 0
		jf: 0
		k: default_action_val
	}

	return filter
}

pub fn apply(config FilterConfig) ! {
	$if linux || android || termux {
		if unsafe { C.prctl(pr_set_no_new_privs, 1, 0, 0, 0) } == -1 {
			return error('failed to set no_new_privs')
		}

		filter_bytecode := build_bpf_filter(config)!

		prog := C.sock_fprog{
			len:    u16(filter_bytecode.len)
			filter: &filter_bytecode[0]
		}

		if unsafe { C.prctl(pr_set_seccomp, seccomp_mode_filter, u64(voidptr(&prog)), 0, 0) } == -1 {
			return error('failed to load raw bpf filter')
		}
	} $else {
		return error('bpf filtering is only supported on linux, android, and termux')
	}
}

pub fn block(syscalls []Syscall) ! {
	mut rules := []SyscallRule{cap: syscalls.len}
	for sys in syscalls {
		rules << SyscallRule{
			sys: sys
			action: .kill_process
		}
	}
	apply(
		filter_type: .blocklist
		rules: rules
	)!
}

pub fn block_with_errno(syscalls []Syscall, errno_code int) ! {
	mut rules := []SyscallRule{cap: syscalls.len}
	for sys in syscalls {
		rules << SyscallRule{
			sys: sys
			action: .errno_error
		}
	}
	apply(
		filter_type: .blocklist
		rules: rules
		errno_code: errno_code
	)!
}

pub fn allow(syscalls []Syscall) ! {
	mut rules := []SyscallRule{cap: syscalls.len}
	for sys in syscalls {
		rules << SyscallRule{
			sys: sys
			action: .allow
		}
	}
	apply(
		filter_type: .allowlist
		rules: rules
	)!
}
