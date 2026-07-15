import vcomp

fn main() {
	vcomp.call('write', 1, 'Hello World\n', 12) or {
		println(err)
		return
	}
}
