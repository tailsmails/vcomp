# vcomp

`vcomp` is a lightweight Linux Seccomp (Secure Computing Mode) BPF filter wrapper written in V. It helps restrict the system calls a process can make, providing an extra layer of security for sandbox environments or untrusted code execution.

## Features

- **Comprehensive Upstream Syscall Coverage**: Automatically generated directly from the official Linux kernel git tree on GitHub, covering 100% of all native system calls.
- **Blocklist & Allowlist**: Easily block or restrict syscalls.
- **Custom Actions**: Supports `kill_process`, `kill_thread`, `trap`, `allow`, and custom `errno` codes.
- **Multi-Arch Support**: Resolves syscall names for `amd64` (x86_64), `arm64`, `i386`, `arm32`, and `rv64` (RISC-V 64).
- **Flexible Input**: Accepts syscalls as either `string` names or raw `int` numbers.

## Installation

You can install this module using the V package manager:

```bash
v install --git https://github.com/tailsmails/vcomp
```

## Syscall Table Generator (For Developers)

The repository includes a generator script that fetches the latest official system call numbers for all supported architectures directly from the upstream Linux kernel source repository.

To update or regenerate the syscall table:

```bash
python3 syscall_res.py
```

This writes the unified, multi-arch `syscalls.v` table containing complete mappings for all architectures.

## Quick Start Example

```v
import vcomp
import os

fn C.syscall(number int, arg1 voidptr, arg2 voidptr, arg3 voidptr, arg4 voidptr) int

fn main() {
	println('Applying BPF filter...')

	vcomp.block_with_errno(['ptrace'], 1) or {
		println('Failed to apply filter: ${err}')
		return
	}

	println('Filter applied successfully!')
	println('Testing ptrace block...')

	ptrace_num := vcomp.get_syscall_number('ptrace') or {
		println(err)
		return
	}

	res := unsafe { C.syscall(ptrace_num, voidptr(0), voidptr(0), voidptr(0), voidptr(0)) }
	if res == -1 {
		err_msg := os.error_posix()
		println('ptrace failed as expected! Error details: ${err_msg}')
	} else {
		println('WARNING: ptrace call was allowed.')
	}
}
```

## Supported Platforms

- Linux
- Android
- Termux

## License
![License](https://img.shields.io/badge/License-MIT-red.svg)
