import vcomp
import os

fn C.syscall(number int, arg1 voidptr, arg2 voidptr, arg3 voidptr, arg4 voidptr) int

fn main() {
	println('Applying BPF filter...')

	vcomp.block_with_errno(['ptrace'], 1) or {
		println('Failed to apply filter: $err')
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