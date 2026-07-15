import vcomp

fn main() {
	println('Applying conditional filter...')

	vcomp.new_filter()
		.set_type(.allowlist)
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
