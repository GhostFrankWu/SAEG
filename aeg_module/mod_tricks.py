# May add some tricks such as:
# short jump to [libc_start_main -n]\call vuln\read
# hijack __stack_chk_fail, __dl_fini...

from .challenge import Challenge
from .binary_interactive import InteractiveBinary
from .utils import *


class Tricks:
    def __init__(self, trick_name, trick_func, require_disabled_protections, required_information):
        log.info(
            f'Load exploit: {trick_name}, need binary without or bypassed {require_disabled_protections}, '
            f'need {required_information}')
        self.name = trick_name
        self.trick_func = trick_func
        self.require_disabled_protections = require_disabled_protections
        self.required_information = required_information
        self.available = True

    def run(self, state_raw: angr.SimState, challenge: Challenge, new_mem: list):
        log.info(f"Trying trick {self.name}")
        try:
            return self.trick_func(state_raw, challenge, new_mem)
        except Exception as e:
            raise e

    def satisfy(self, binary: InteractiveBinary, try_lazy=False):
        return self.available and \
            all([i in binary.io_seg_addr for i in self.required_information]) and \
            all([not binary.challenge.protection[i] for i in self.require_disabled_protections]) and \
            binary.payload_len >= binary.arch_bytes * self.name - 1
