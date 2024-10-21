import copy

from pwn import *
from pwn import p32, p64, u32, u64
from pwnlib.elf.elf import dotdict

from .mod_sim_procedure import *
from .mod_sim_procedure_heap import *
from .utils import get_win_functions, known_flag_names, pre_process_flirt, FlagFound
import angr.procedures.libc.scanf
import r2pipe


class Challenge:
    def preprocess(self):
        self._init_hook_table()
        self._init_func()

    def do_hook(self, angr_proj, base=0):
        log.info(f"Hooking functions{f' with base {hex(base)}' if base else ''}")

        for func_name, func in self.target_binary.functions.items():
            if func_name in self.hook_table.keys():
                log.info(f"Hook {func_name} at {hex(func.address)}")
                angr_proj.hook(func.address + base, self.hook_table[func_name])
        for func_name, addr in self.target_binary.symbols.items():
            if func_name in self.hook_table.keys() and func_name not in self.target_binary.functions:
                log.info(f"Hook {func_name} at {hex(addr)}")
                angr_proj.hook(addr + base, self.hook_table[func_name])
        for func_name, func in self.function_list:
            if func_name in self.hook_table.keys() and self.target_binary.functions.get(func_name) != func.address:
                log.info(f"Hook {func_name} at {hex(func.address)}")
                angr_proj.hook(func.address + base, self.hook_table[func_name])

    def _init_hook_table(self):
        log.info("Init hook table...")
        self.hook_table = {  # For zeratool check
            'server_main': ServerMain64LibPWNAbleHarness() if self.target_property['arch_bytes'] == 8 else
            ServerMain32LibPWNAbleHarness()
        }
        if self.target_property['static']:
            self.hook_table = dict(self.hook_table, **{k: v() for k, v in angr.SIM_PROCEDURES['libc'].items()})
            self.hook_table = dict(self.hook_table, **{k: v() for k, v in angr.SIM_PROCEDURES['glibc'].items()})
            self.hook_table = dict(self.hook_table, **{k: v() for k, v in angr.SIM_PROCEDURES['posix'].items()})
        self.hook_table = dict(self.hook_table, **{  # Note that this order is to overwrite angr;s hook
            'gets': ReplaceGets(self),
            'read': ReplaceRead(self),
            'alarm': ReplaceAlarm(),
            'setvbuf': ReplaceSetBuf(),
            'puts': ReplacePuts(self),
            'printf': ReplacePrintf(self),
            # '__isoc99_scanf': ReplaceC99Scanf(),
            'malloc': ReplaceMalloc(self),
            '__cxa_allocate_exception': ReplaceCxaAllocateException(),
            # 'atol': ReplaceAtol(self),
            'system': ReplaceSystem(),
            'execve': ReplaceSystem(),
        })

    def _init_func(self):
        log.info("Init functions and try find win function...")
        func = self.target_binary.symbols
        if self.target_binary.linker:
            log.info("Binary is dynamically linked")
            self.segment_address['dynamic'] = 1
        else:
            self.segment_address['static'] = 1
            log.info("Binary is statically linked")
            self.target_property['static'] = True
            if len(self.target_binary.functions) < 3:
                self.function_list = pre_process_flirt(self)
                self.target_binary.functions = dotdict({k: v for k, v in self.function_list})
                for k, v in self.target_binary.functions.items():
                    self.target_binary.symbols[k] = v.address  # symbols is for ROP resolvable.

        for win_name in ['get_flag', 'win', 'backdoor']:
            self.segment_address['win_func'].append(func[win_name] + 1) if win_name in func else None
        if 'system' in self.target_binary.functions:
            self.segment_address['backdoor'] = self.target_binary.functions['system'].address
        log.info(f'Searching for interesting strings')
        for backdoor_str in known_flag_names:
            try:
                if next(self.target_binary.search(backdoor_str.encode())):
                    log.info(f'Found interesting string in binary: {backdoor_str}')
                    win_func = get_win_functions(self)  # r2 is very slow, so we only call it when necessary
                    if win_func:
                        self.segment_address['win_func'] += list(set(win_func))
                    break
            except StopIteration:
                continue
        if self.segment_address.get('win_func'):
            log.info(f"Contains win function {[hex(x) for x in self.segment_address['win_func']]}")
        else:
            self.segment_address.pop('win_func')

        if self.segment_address.get('backdoor'):
            for possible_cmd in [b'cat flag', b'cat /flag', b'bin/bash', b'bin/sh', b'sh\x00', b'/bin/sh',
                                 b'/bin/bash']:
                try:
                    cmd_str = next(self.target_binary.search(possible_cmd))
                    if cmd_str:
                        self.segment_address['cmd_str'] = cmd_str
                        log.info(f"Found string {cmd_str} as system args at {hex(self.segment_address['backdoor'])}")
                        break
                except StopIteration:
                    continue

        context.arch = self.target_property['arch']
        if not self.protection['NX']:
            jmp_esp = self.rop.jmp_esp if '64' not in self.target_binary.arch else self.rop.jmp_rsp
            if jmp_esp:
                self.segment_address['jmp_esp'] = jmp_esp[0]

    def __init__(self, binary, flag_path=None, libc=None, ld=None):
        self.target_binary = ELF(binary)
        self.rop = ROP([self.target_binary])
        self.r2_pipe = None
        self.r2_ana_op = []
        self.function_list = []
        self.backward_search = 0xfe
        self.backward_addr_list = []

        self.le = p32 if '64' not in self.target_binary.arch else p64
        self.rle = u32 if '64' not in self.target_binary.arch else u64

        self.segment_address = {
            'stdout_offset': 0,
            'stdin_offset': 0,
            'win_func': [],
        }

        self.protection = {
            'Canary': self.target_binary.canary and self.target_binary.linker, 
            # cnaary check in checksec is not reliable, we may update it by other method for 100% accuracy
            'NX': self.target_binary.nx,
            'PIE': self.target_binary.pie,
            'RELRO': self.target_binary.relro and 'Full' in self.target_binary.relro,
        }

        if not self.target_binary.pie:
            self.segment_address['text'] = 0

        self.target_property = {
            'static': self.target_binary.linker is None,
            'file': binary,
            'arch': self.target_binary.arch,
            'flirt': '../assets/laeg/libc6_2.27-0ubuntu3_amd64.sig',
            'plt': self.target_binary.plt,
            'flag_path': flag_path,
            'bss_addr': [],
            'arch_bytes': 4 if '64' not in self.target_binary.arch else 8,
            'libc': libc,
            'ld': ld,
        }

        log.info(f"Specify arch as {self.target_property['arch']}")
        context.arch = self.target_property['arch']
        self.target_property['arch_bytes'] = 4 if '64' not in self.target_property['arch'] else 8
        if not self.target_property['libc']:
            self.target_property['libc'] = '/lib/i386-linux-gnu/libc.so.6' \
                if self.target_property['arch_bytes'] == 4 else '/lib/x86_64-linux-gnu/libc.so.6'
        self.hook_table = {}

    def get_r2(self):
        if self.r2_pipe is None:
            self.r2_pipe = r2pipe.open(self.target_property['file'], flags=['-2'])
        return self.r2_pipe

    def r2_op(self, op_):
        if op_ in self.r2_ana_op:
            return
        self.r2_ana_op.append(op_)
        log.info(f"Use {op_} to analyze binary")
        self.r2_pipe.cmd(op_)
        log.info(f"Analyze done")

    def get_segment_address_copy(self):
        return copy.deepcopy(self.segment_address)
