import urllib.request
import re
import os

sources = {
    'amd64': {
        'type': 'tbl',
        'abis': ['common', '64'],
        'url': 'https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/entry/syscalls/syscall_64.tbl'
    },
    'i386': {
        'type': 'tbl',
        'abis': ['common', 'i386'],
        'url': 'https://raw.githubusercontent.com/torvalds/linux/master/arch/x86/entry/syscalls/syscall_32.tbl'
    },
    'arm32': {
        'type': 'tbl',
        'abis': ['common', 'eabi', 'oabi'],
        'url': 'https://raw.githubusercontent.com/torvalds/linux/master/arch/arm/tools/syscall.tbl'
    },
    'arm64': {
        'type': 'h',
        'url': 'https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/asm-generic/unistd.h'
    },
    'rv64': {
        'type': 'h',
        'url': 'https://raw.githubusercontent.com/torvalds/linux/master/include/uapi/asm-generic/unistd.h'
    }
}

def parse_tbl(content, allowed_abis):
    syscalls = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split()
        if len(parts) >= 3:
            if parts[0].isdigit():
                sys_id = int(parts[0])
                abi = parts[1]
                sys_name = parts[2]
                if abi in allowed_abis:
                    syscalls[sys_name] = sys_id
    return syscalls

def parse_h(content):
    syscalls = {}
    matches = re.findall(r'#define\s+__NR_(\w+)\s+(\d+)', content)
    for name, num in matches:
        sys_id = int(num)
        syscalls[name] = sys_id
    return syscalls

out = []
out.append('module vcomp')
out.append('')
out.append('fn resolve_syscall(sys Syscall) !int {')
out.append('\tmatch sys {')
out.append('\t\tint {')
out.append('\t\t\treturn sys')
out.append('\t\t}')
out.append('\t\tstring {')

first = True
for v_arch, info in sources.items():
    print(f"Fetching syscalls for {v_arch} from github/torvalds...")
    try:
        req = urllib.request.Request(info['url'], headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            content = response.read().decode('utf-8')
    except Exception as e:
        print(f"Failed to fetch {v_arch}: {e}")
        continue

    if info['type'] == 'tbl':
        syscalls = parse_tbl(content, info['abis'])
    else:
        syscalls = parse_h(content)

    if first:
        out.append(f'\t\t\t$if {v_arch} {{')
        first = False
    else:
        out.append(f'\t\t\t}} $else $if {v_arch} {{')

    out.append('\t\t\t\tmatch sys {')
    for name, sys_id in syscalls.items():
        out.append(f"\t\t\t\t\t'{name}' {{ return {sys_id} }}")
    out.append("\t\t\t\t\telse { return error('syscall \"' + sys + '\" is not supported on this architecture') }")
    out.append('\t\t\t\t}')

out.append('\t\t\t} $else {')
out.append("\t\t\t\treturn error('architecture not supported for string syscall lookup')")
out.append('\t\t\t}')
out.append('\t\t}')
out.append('\t}')
out.append('}')

script_dir = os.path.dirname(os.path.realpath(__file__))
target_path = os.path.join(script_dir, 'syscalls.v')

with open(target_path, 'w', encoding='utf-8') as f:
    f.write('\n'.join(out))

print(f"File syscalls.v successfully created in {target_path}")
