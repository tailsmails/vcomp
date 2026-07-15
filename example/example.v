import vcomp

fn main() {
	println('Applying BPF filter...')

	vcomp.new_filter()
		.set_type(.allowlist)
		.allow('write').where_arg(0, .eq, 1)
		.allow('exit_group')
		.allow('exit')
		.allow('close')
		.allow('munmap')
		.allow('mprotect')
		.apply() or {
			println('Failed to apply filter: ${err}')
			return
		}

	println('Testing write to stdout (FD 1)...')

	vcomp.call('write', 1, 'This is allowed and will exit cleanly!\n', 38) or {
		println(err)
		return
	}
}
