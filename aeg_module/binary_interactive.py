import copy

from .utils import *


class InteractiveBinary:
    def __init__(self, file, flag_path, challenge, io_property, io_seg_addr, arch_bytes,
                 leak_path=None, ip=None, port=None, depth=0, interactive=False):
        self.new_stack_addr, self.new_stack_symbol = None, None
        self.leak_path = [] if leak_path is None else leak_path
        self.file = file
        self.flag_path = flag_path
        self.io_property = io_property
        self.io_seg_addr = io_seg_addr
        self.ip = ip
        self.port = port
        self.challenge = challenge
        self.libc = challenge.target_property['libc']
        self.ld = challenge.target_property['ld']
        self.arch_bytes = arch_bytes
        self.chunk_maps = {}
        self.current_process = None
        self.rop_address = challenge.target_binary.entry
        self.constant_to_be_add = []
        self.payload_len = 0
        self.overflow_mem = None
        self.fmt_var_offset = None
        self.le = p32 if 4 == self.arch_bytes else p64
        self.rle = u32 if 4 == self.arch_bytes else u64
        # depth is for accelerating dfs search, if not returned, the child can continue use the parent's process
        self.depth = depth
        self.io_depth = 0
        self.interactive = interactive

    def __copy__(self):
        new_binary = InteractiveBinary(self.file, self.flag_path, self.challenge, copy.deepcopy(self.io_property),
                                       copy.deepcopy(self.io_seg_addr), self.arch_bytes, copy.deepcopy(self.leak_path),
                                       self.ip, self.port, self.depth + 1, self.interactive)
        new_binary.chunk_maps = copy.deepcopy(self.chunk_maps)
        new_binary.rop_address = self.rop_address
        new_binary.payload_len = self.payload_len
        new_binary.new_stack_addr = self.new_stack_addr
        new_binary.new_stack_symbol = self.new_stack_symbol

        new_binary.current_process = self.current_process  # pass to child to accelerate dfs search
        return new_binary

    def connect(self, state):
        """
        Note: this function will close the current process, and run every leak and mitigation path for the new process
        """
        for _ in range(3):
            self.close()
            state.globals['binary'] = self
            self.io_seg_addr = copy.deepcopy(self.io_seg_addr)
            if self.ip:
                context.timeout = 5
                self.current_process = remote(self.ip, self.port)
                context.timeout = 0.3
            else:
                context.timeout = 0.01
                if self.libc:
                    if self.ld:
                        self.current_process = process([self.ld, self.file], env={"LD_PRELOAD": self.libc})
                    else:
                        self.current_process = process([self.file], env={"LD_PRELOAD": self.libc})
                else:
                    self.current_process = process([self.file])
            if self.leak_path:
                for p in self.leak_path:
                    if not p.run(state.copy(), self.challenge, self.overflow_mem):
                        break
                    elif p == self.leak_path[-1]:
                        return
            else:
                return

    def check_alive(self):
        if self.current_process is None:
            return True  # never used interact mode
        try:
            self.current_process.unrecv(self.current_process.recvn(0x10, timeout=context.timeout * 2))
            return self.current_process is not None and (self.ip is not None or self.current_process.poll() is None)
        except EOFError:
            return False

    def warped_io(self, state, data_to_send=None, check_alive=True, has_newline=True):
        if self.io_depth > self.depth:
            self.close()  # returned from child state, reconnect
        self.io_depth = self.depth
        if check_alive:
            if not self.current_process:
                self.connect(state)
        elif not self.current_process:
            return None
        try:
            flag = self.current_process.recvrepeat(timeout=context.timeout)
            if data_to_send:
                if has_newline:
                    self.current_process.sendline(data_to_send)
                else:
                    self.current_process.send(data_to_send)
            else:
                # Important: Change the format of flag if necessary
                if b'flag{' in flag and b'}' in flag:
                    log.success(f"Win! Received: {flag}")
                    log.success(f"Reporting flag as: {re.findall(b'flag{.*}', flag)[0]}")
                    if self.interactive:
                        self.current_process.interactive()
                    self.close()
                    raise FlagFound(flag)
                if b"version `GLIBC_2." in flag and b"' not found (required by " in flag:
                    log.success(f"Win locally! Received: {flag}")
                    self.close()
                    raise FlagFound(b'=====locally success, consider patchelf=====' + flag)
            return flag
        except EOFError:
            self.close()

    def warped_io_strip_zero(self, state, data_to_send=None, check_alive=True, is_raw=False):
        self.warped_io(state, strip_zero_in_payload(data_to_send, is_raw), check_alive=check_alive)

    def close(self):
        if self.current_process:
            try:
                self.current_process.close()
            except BrokenPipeError:
                pass
            self.current_process = None
            self.io_seg_addr = copy.deepcopy(self.challenge.segment_address)

    def get_flag(self, state, payload, has_newline=True):
        payload = strip_zero_in_payload(payload, not has_newline)
        self.warped_io(state, check_alive=True)
        # gdb.attach(self.current_process)
        # input()
        self.warped_io(state, payload, check_alive=False, has_newline=has_newline)
        # input()
        self.warped_io(state, check_alive=False)
        self.warped_io(state, f"\ncat {self.flag_path}".encode('ascii') * 2, check_alive=False)
        self.warped_io(state, check_alive=False)
        self.warped_io(state, check_alive=False)
        # self.current_process.interactive()
        self.close()
        log.failure("Failed for this try")

    def send_payload(self, state, payload, check_alive=True):
        payload = strip_zero_in_payload(payload)
        return self.warped_io(state, payload, check_alive)
