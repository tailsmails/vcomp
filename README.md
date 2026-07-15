# vcomp

`vcomp` is a lightweight Linux Seccomp (Secure Computing Mode) BPF filter wrapper written in V. It helps restrict the system calls a process can make, providing an extra layer of security for sandbox environments or untrusted code execution.

## Features

- **Comprehensive Upstream Syscall Coverage**: Automatically generated directly from the official Linux kernel git tree on GitHub, covering 100% of all native system calls.
- **User-Friendly Syscall Invocation**: Execute raw system calls cleanly via `vcomp.call` without manually declaring C functions or using `unsafe` blocks.
- **Fluent API / Builder Pattern**: Easily construct complex rule sets using method chaining.
- **Advanced Argument Filtering**: Inspect and restrict 64-bit system call arguments directly from V.
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

fn main() {
	println('Applying BPF filter...')

	mut filter := vcomp.new_filter()
	filter.set_type(.allowlist)
		.allow('write').where_arg(0, .eq, 1)
		.allow('exit_group')
		.apply() or {
			println('Failed to apply filter: ${err}')
			return
		}

	println('Filter applied successfully!')
	println('Testing write to stdout (FD 1)...')

	vcomp.call('write', 1, 'This is allowed!\n', 17) or {
		println(err)
		return
	}

	println('Testing write to stderr (FD 2)...')

	vcomp.call('write', 2, 'This will be blocked!\n', 22) or {
		println('Error: ${err}')
		return
	}
}
```

## Builder API Reference

- `new_filter()`: Creates a new builder instance.
- `set_type(t FilterType)`: Configures the filter behavior (`.blocklist` or `.allowlist`).
- `set_errno(code int)`: Sets the default POSIX errno code returned when `block_with_errno` triggers.
- `block(sys Syscall)`: Appends a system call blocking rule (`.kill_process`).
- `block_with_errno(sys Syscall)`: Appends a system call blocking rule that returns a specific errno.
- `allow(sys Syscall)`: Appends a system call allow rule (`.allow`).
- `where_arg(index int, op Op, value u64)`: Adds a 64-bit argument constraint to the last appended rule.
- `apply()`: Evaluates the configuration, compiles BPF bytecode, and activates the Seccomp filter.

## Supported Platforms

- Linux
- Android
- Termux

## License
![License](https://img.shields.io/badge/License-MIT-red.svg)
