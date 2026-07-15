import vcomp

fn main() {
	println('Applying BPF filter...')

	vcomp.block_with_errno(['ptrace'], 1) or {
		println('Failed to apply filter: ${err}')
		return
	}

	println('Filter applied successfully!')
	println('Testing ptrace block...')

	res := vcomp.call('ptrace', 0, 0, 0, 0) or {
		println('ptrace failed as expected! Error details: ${err}')
		return
	}
	println('WARNING: ptrace call was allowed. Result: ${res}')
}
